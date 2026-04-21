package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"simple_auth/internal/conf"
)

func TestNewLoggerWritesToConfiguredFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "simple_auth.log")
	logger, closeLogger, err := newLogger(&conf.Bootstrap{
		Logging: &conf.Logging{
			FilePath: path,
		},
	})
	if err != nil {
		t.Fatalf("newLogger() error = %v", err)
	}

	if err := logger.Log(0, "msg", "hello file logger"); err != nil {
		t.Fatalf("logger.Log() error = %v", err)
	}
	closeLogger()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(content), "hello file logger") {
		t.Fatalf("log file content = %q", string(content))
	}
}
