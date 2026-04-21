package conf_test

import (
	"testing"

	"simple_auth/internal/conf"

	"github.com/go-kratos/kratos/v2/config"
	"github.com/go-kratos/kratos/v2/config/file"
)

func TestConfigYAMLScansBootstrap(t *testing.T) {
	c := config.New(config.WithSource(file.NewSource("../../configs")))
	defer c.Close()
	if err := c.Load(); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	var bc conf.Bootstrap
	if err := c.Scan(&bc); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if bc.GetServer().GetHttp().GetAddr() != "0.0.0.0:8000" {
		t.Fatalf("http addr = %q", bc.GetServer().GetHttp().GetAddr())
	}
	if bc.GetSession().GetCookieName() != "auth_session" {
		t.Fatalf("cookie name = %q", bc.GetSession().GetCookieName())
	}
	if len(bc.GetUsers()) == 0 {
		t.Fatal("expected configured users")
	}
	if !bc.GetSecurity().GetLoginFailure().GetUserWhitelistEnabled() {
		t.Fatal("expected user whitelist to be enabled")
	}
	if bc.GetLogging().GetFilePath() != "" {
		t.Fatalf("log file path = %q", bc.GetLogging().GetFilePath())
	}
}
