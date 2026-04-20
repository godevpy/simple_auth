package server

import (
	stdHTTP "net/http"

	"simple_auth/internal/conf"
	"simple_auth/internal/service"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/recovery"
	"github.com/go-kratos/kratos/v2/transport/http"
)

// NewHTTPServer new an HTTP server.
func NewHTTPServer(c *conf.Bootstrap, auth *service.AuthService, logger log.Logger) *http.Server {
	var opts = []http.ServerOption{
		http.Middleware(
			recovery.Recovery(),
		),
	}
	httpConf := c.GetServer().GetHttp()
	if httpConf.GetNetwork() != "" {
		opts = append(opts, http.Network(httpConf.GetNetwork()))
	}
	if httpConf.GetAddr() != "" {
		opts = append(opts, http.Address(httpConf.GetAddr()))
	}
	if httpConf.GetTimeout() != nil {
		opts = append(opts, http.Timeout(httpConf.GetTimeout().AsDuration()))
	}
	srv := http.NewServer(opts...)
	srv.HandleFunc("/login", func(w stdHTTP.ResponseWriter, r *stdHTTP.Request) {
		if r.Method == stdHTTP.MethodPost {
			auth.Login(w, r)
			return
		}
		auth.LoginPage(w, r)
	})
	srv.HandleFunc("/_auth/verify", auth.Verify)
	srv.HandleFunc("/_auth/logout", auth.Logout)
	srv.HandleFunc("/_auth/me", auth.Me)
	srv.HandleFunc("/_auth/healthz", auth.Healthz)
	srv.HandleFunc("/_auth/readyz", auth.Readyz)
	return srv
}
