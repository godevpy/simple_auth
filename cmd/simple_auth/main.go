package main

import (
	"flag"
	"os"
	"path/filepath"
	"strings"

	"simple_auth/internal/conf"

	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"
	"github.com/go-kratos/kratos/v2/log"
	"github.com/go-kratos/kratos/v2/middleware/tracing"
	"github.com/go-kratos/kratos/v2/transport/http"

	_ "go.uber.org/automaxprocs"
)

// go build -ldflags "-X main.Version=x.y.z"
var (
	// Name is the name of the compiled software.
	Name string
	// Version is the version of the compiled software.
	Version string
	// flagconf is the config flag.
	flagconf string

	id, _ = os.Hostname()
)

func init() {
	flag.StringVar(&flagconf, "conf", "./configs", "config path, eg: -conf config.yaml")
}

func newApp(logger log.Logger, hs *http.Server) *kratos.App {
	return kratos.New(
		kratos.ID(id),
		kratos.Name(Name),
		kratos.Version(Version),
		kratos.Metadata(map[string]string{}),
		kratos.Logger(logger),
		kratos.Server(
			hs,
		),
	)
}

func newLogger(c *conf.Bootstrap) (log.Logger, func(), error) {
	output := strings.TrimSpace(c.GetLogging().GetFilePath())
	switch strings.ToLower(output) {
	case "", "stdout":
		return buildLogger(os.Stdout), func() {}, nil
	case "stderr":
		return buildLogger(os.Stderr), func() {}, nil
	default:
		dir := filepath.Dir(output)
		if dir != "." && dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, nil, err
			}
		}
		f, err := os.OpenFile(output, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, nil, err
		}
		return buildLogger(f), func() { _ = f.Close() }, nil
	}
}

func buildLogger(output *os.File) log.Logger {
	return log.With(log.NewStdLogger(output),
		"ts", log.DefaultTimestamp,
		"caller", log.DefaultCaller,
		"service.id", id,
		"service.name", Name,
		"service.version", Version,
		"trace.id", tracing.TraceID(),
		"span.id", tracing.SpanID(),
	)
}

func main() {
	flag.Parse()
	c := config.New(
		config.WithSource(
			file.NewSource(flagconf),
		),
	)
	defer c.Close()

	if err := c.Load(); err != nil {
		panic(err)
	}

	var bc conf.Bootstrap
	if err := c.Scan(&bc); err != nil {
		panic(err)
	}

	logger, closeLogger, err := newLogger(&bc)
	if err != nil {
		panic(err)
	}
	defer closeLogger()
	helper := log.NewHelper(logger)
	helper.Infof("config loaded: path=%s http_addr=%s redis_addr=%s users=%d authorization_enabled=%t audit_dir=%s log_file=%s",
		flagconf,
		bc.GetServer().GetHttp().GetAddr(),
		bc.GetData().GetRedis().GetAddr(),
		len(bc.GetUsers()),
		bc.GetAuthorization().GetEnabled(),
		bc.GetLogging().GetAudit().GetLoginFailureDir(),
		bc.GetLogging().GetFilePath(),
	)

	app, cleanup, err := wireApp(&bc, logger)
	if err != nil {
		panic(err)
	}
	defer cleanup()

	// start and wait for stop signal
	if err := app.Run(); err != nil {
		panic(err)
	}
}
