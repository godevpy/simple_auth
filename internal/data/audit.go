package data

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"simple_auth/internal/biz"
	"simple_auth/internal/conf"
)

type fileAuditRepo struct {
	dir      string
	pattern  string
	dirMode  os.FileMode
	fileMode os.FileMode
	mu       sync.Mutex
}

func NewAuditRepo(c *conf.Bootstrap) biz.AuditRepo {
	audit := c.GetLogging().GetAudit()
	return &fileAuditRepo{
		dir:      defaultString(audit.GetLoginFailureDir(), "logs"),
		pattern:  defaultString(audit.GetLoginFailureFilePattern(), "login_failure_audit-2006-01-02.jsonl"),
		dirMode:  parseFileMode(audit.GetDirMode(), 0o700),
		fileMode: parseFileMode(audit.GetFileMode(), 0o600),
	}
}

func (r *fileAuditRepo) WriteLoginFailure(_ context.Context, event *biz.LoginFailureEvent) error {
	if event == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := os.MkdirAll(r.dir, r.dirMode); err != nil {
		return err
	}
	name := event.Time.Local().Format(r.pattern)
	path := filepath.Join(r.dir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, r.fileMode)
	if err != nil {
		return err
	}
	defer f.Close()
	_ = f.Chmod(r.fileMode)
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, string(raw)); err != nil {
		return err
	}
	return nil
}

func parseFileMode(value string, fallback os.FileMode) os.FileMode {
	if value == "" {
		return fallback
	}
	n, err := strconv.ParseUint(value, 8, 32)
	if err != nil {
		return fallback
	}
	return os.FileMode(n)
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
