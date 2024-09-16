package restserver

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/handlers"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/restic/rest-server/quota"
)

func (s *Server) debugHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s %s", r.Method, r.URL)
			next.ServeHTTP(w, r)
		})
}

func (s *Server) logHandler(next http.Handler) http.Handler {
	var accessLog io.Writer

	if s.Log == "-" {
		accessLog = os.Stdout
	} else {
		var err error
		accessLog, err = os.OpenFile(s.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
	}

	return handlers.CombinedLoggingHandler(accessLog, next)
}

func (s *Server) checkAuth(r *http.Request) (username string, ok bool) {
	if s.AuthType == AuthTypeNone {
		return username, true
	} else if s.AuthType == AuthTypeHttpXRemoteUser {
		username = strings.TrimSpace(r.Header.Get("X-Remote-User"))
		if username != "" && validUsernameRegexp.MatchString(username) {
			return username, true
		}
	} else if s.AuthType == AuthTypeHtpasswd {
		var password string
		username, password, ok = r.BasicAuth()
		if ok && s.htpasswdFile.Validate(username, password) {
			return username, true
		}
	}
	return username, false
}

func (s *Server) wrapMetricsAuth(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, ok := s.checkAuth(r)
		if !ok {
			httpDefaultError(w, http.StatusUnauthorized)
			return
		}
		if s.PrivateRepos && username != "metrics" {
			httpDefaultError(w, http.StatusUnauthorized)
			return
		}
		f(w, r)
	}
}

// NewHandler returns the master HTTP multiplexer/router.
func NewHandler(server *Server) (http.Handler, error) {
	if server.AuthType == AuthTypeHtpasswd {
		var err error
		if server.HtpasswdPath == "" {
			server.HtpasswdPath = filepath.Join(server.Path, ".htpasswd")
		}
		server.htpasswdFile, err = NewHtpasswdFromFile(server.HtpasswdPath)
		if err != nil {
			return nil, fmt.Errorf("cannot load %s (use a different --auth-type or set --auth-type to 'none' to disable authentication): %v",
				server.HtpasswdPath, err)
		}
		log.Printf("Loaded htpasswd file %s", server.HtpasswdPath)
	}

	const GiB = 1024 * 1024 * 1024

	if server.MaxRepoSize > 0 {
		log.Printf("Initializing quota (can take a while)...")
		qm, err := quota.New(server.Path, server.MaxRepoSize)
		if err != nil {
			return nil, err
		}
		server.quotaManager = qm
		log.Printf("Quota initialized, currently using %.2f GiB", float64(qm.SpaceUsed())/GiB)
	}

	mux := http.NewServeMux()
	if server.Prometheus {
		if server.PrometheusNoAuth {
			mux.Handle("/metrics", promhttp.Handler())
		} else {
			mux.HandleFunc("/metrics", server.wrapMetricsAuth(promhttp.Handler().ServeHTTP))
		}
	}
	mux.Handle("/", server)

	var handler http.Handler = mux
	if server.Debug {
		handler = server.debugHandler(handler)
	}
	if server.Log != "" {
		handler = server.logHandler(handler)
	}
	return handler, nil
}
