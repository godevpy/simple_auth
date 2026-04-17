package data

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"simple_auth/internal/biz"
	"simple_auth/internal/conf"
)

func TestFileAuditRepoWritesDailyJSONLWithoutPlaintextPassword(t *testing.T) {
	dir := t.TempDir()
	repo := NewAuditRepo(&conf.Bootstrap{
		Logging: &conf.Logging{
			Audit: &conf.Logging_Audit{
				LoginFailureDir:         dir,
				LoginFailureFilePattern: "login_failure_audit-2006-01-02.jsonl",
				FileMode:                "0600",
				DirMode:                 "0700",
			},
		},
	})
	event := &biz.LoginFailureEvent{
		Time:                time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC),
		IP:                  "203.0.113.10",
		Username:            "alice",
		UserAgent:           "test-agent",
		Reason:              "bad_password",
		BanResult:           "none",
		PasswordAttemptHMAC: "fingerprint",
	}
	if err := repo.WriteLoginFailure(context.Background(), event); err != nil {
		t.Fatalf("WriteLoginFailure() error = %v", err)
	}
	path := filepath.Join(dir, "login_failure_audit-2026-04-17.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	content := string(raw)
	if !strings.Contains(content, `"username":"alice"`) {
		t.Fatalf("audit content missing username: %s", content)
	}
	if !strings.Contains(content, `"password_attempt_hmac":"fingerprint"`) {
		t.Fatalf("audit content missing password fingerprint: %s", content)
	}
	if strings.Contains(content, "wrong-password") {
		t.Fatalf("audit content must not include plaintext password: %s", content)
	}
}
