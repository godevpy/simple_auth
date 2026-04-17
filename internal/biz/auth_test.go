package biz

import (
	"context"
	"errors"
	"testing"
	"time"

	"simple_auth/internal/conf"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestAuthUsecaseLoginSuccessCreatesSession(t *testing.T) {
	uc, sessions, failures, _ := newTestAuthUsecase(t)

	result, err := uc.Login(context.Background(), LoginInput{
		Username:  "alice",
		Password:  "secret",
		Host:      "App.Example.Com",
		ClientIP:  "203.0.113.10",
		UserAgent: "test-agent",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if result.SessionID == "" {
		t.Fatal("Login() returned empty session id")
	}
	if result.Session.Host != "app.example.com" {
		t.Fatalf("session host = %q", result.Session.Host)
	}
	if sessions.lastTTL > 30*time.Minute || sessions.lastTTL <= 0 {
		t.Fatalf("session ttl = %v", sessions.lastTTL)
	}
	if !failures.cleared {
		t.Fatal("expected login success to clear failure counters")
	}
}

func TestAuthUsecaseLoginFailureBansAndAuditsWithoutPlaintext(t *testing.T) {
	uc, _, failures, audit := newTestAuthUsecase(t)

	for i := 0; i < 3; i++ {
		_, err := uc.Login(context.Background(), LoginInput{
			Username:  "alice",
			Password:  "wrong-password",
			Host:      "app.example.com",
			ClientIP:  "203.0.113.10",
			UserAgent: "test-agent",
		})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("Login() error = %v, want ErrInvalidCredentials", err)
		}
	}
	if !failures.ipBans["203.0.113.10"] {
		t.Fatal("expected IP to be banned after 3 failures")
	}
	if !failures.userBans["alice"] {
		t.Fatal("expected user to be banned after 3 failures")
	}
	if len(audit.events) != 3 {
		t.Fatalf("audit events = %d, want 3", len(audit.events))
	}
	last := audit.events[len(audit.events)-1]
	if last.PasswordAttemptHMAC == "" {
		t.Fatal("expected password attempt HMAC")
	}
	if last.PasswordAttemptHMAC == "wrong-password" {
		t.Fatal("audit must not record plaintext password")
	}
}

func TestAuthUsecaseNonWhitelistedUserBansIP(t *testing.T) {
	uc, _, failures, audit := newTestAuthUsecase(t)

	_, err := uc.Login(context.Background(), LoginInput{
		Username:  "mallory",
		Password:  "anything",
		Host:      "app.example.com",
		ClientIP:  "203.0.113.20",
		UserAgent: "test-agent",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want ErrInvalidCredentials", err)
	}
	if !failures.ipBans["203.0.113.20"] {
		t.Fatal("expected non-whitelisted user to ban IP")
	}
	if got := audit.events[0].Reason; got != "non_whitelisted_user" {
		t.Fatalf("audit reason = %q", got)
	}
}

func TestAuthUsecaseVerifyAuthorization(t *testing.T) {
	uc, sessions, _, _ := newTestAuthUsecase(t)
	now := time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC)
	uc.now = func() time.Time { return now }
	sessionID := "session-token"
	session := &Session{
		SessionIDHash: HashToken(sessionID),
		UserID:        "user-001",
		Username:      "alice",
		Groups:        []string{"admin"},
		Host:          "app.example.com",
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(time.Hour),
	}
	if err := sessions.Save(context.Background(), sessionID, session, time.Minute); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	if _, err := uc.Verify(context.Background(), VerifyInput{
		SessionID: sessionID,
		Host:      "app.example.com",
		URI:       "/admin/dashboard?tab=1",
		Method:    "GET",
	}); err != nil {
		t.Fatalf("Verify() allowed path error = %v", err)
	}
	if _, err := uc.Verify(context.Background(), VerifyInput{
		SessionID: sessionID,
		Host:      "app.example.com",
		URI:       "/unknown",
		Method:    "GET",
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Verify() denied path error = %v, want ErrForbidden", err)
	}
	if _, err := uc.Verify(context.Background(), VerifyInput{
		SessionID: "missing",
		Host:      "app.example.com",
		URI:       "/admin/dashboard",
		Method:    "GET",
	}); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("Verify() missing session error = %v, want ErrUnauthorized", err)
	}
}

func TestAuthorizationWildcard(t *testing.T) {
	az, err := NewAuthorizationUsecase(testBootstrap(t))
	if err != nil {
		t.Fatalf("NewAuthorizationUsecase() error = %v", err)
	}
	if !az.Allow(AuthorizationInput{
		Host:   "app.example.com",
		URI:    "/ops/blue/dashboard",
		Method: "GET",
		User:   &User{Username: "alice"},
	}) {
		t.Fatal("expected wildcard rule to allow request")
	}
}

func newTestAuthUsecase(t *testing.T) (*AuthUsecase, *fakeSessionRepo, *fakeFailureRepo, *fakeAuditRepo) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	users := &fakeUserRepo{
		users: map[string]*User{
			"alice": {
				ID:           "user-001",
				Username:     "alice",
				DisplayName:  "Alice",
				PasswordHash: string(hash),
				Groups:       []string{"admin"},
			},
		},
		whitelist: map[string]bool{"alice": true},
	}
	sessions := newFakeSessionRepo()
	failures := newFakeFailureRepo()
	audit := &fakeAuditRepo{}
	az, err := NewAuthorizationUsecase(testBootstrap(t))
	if err != nil {
		t.Fatalf("NewAuthorizationUsecase() error = %v", err)
	}
	uc := NewAuthUsecase(users, sessions, failures, audit, az, testBootstrap(t), nil)
	uc.now = func() time.Time { return time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC) }
	return uc, sessions, failures, audit
}

func testBootstrap(t *testing.T) *conf.Bootstrap {
	t.Helper()
	return &conf.Bootstrap{
		Session: &conf.Session{
			CookieName:        "auth_session",
			IdleTimeout:       durationpb.New(30 * time.Minute),
			AbsoluteTimeout:   durationpb.New(24 * time.Hour),
			SlidingExpiration: true,
		},
		Security: &conf.Security{
			LoginFailure: &conf.Security_LoginFailure{
				MaxAttempts:               3,
				Window:                    durationpb.New(30 * time.Minute),
				BanDuration:               durationpb.New(30 * time.Minute),
				BanIp:                     true,
				BanUser:                   true,
				UserWhitelistEnabled:      true,
				UserWhitelist:             []string{"alice"},
				BanIpOnNonWhitelistedUser: true,
				PasswordAttemptAudit:      "hmac",
				PasswordAttemptHmacSecret: "audit-secret",
			},
		},
		Authorization: &conf.Authorization{
			Enabled: true,
			Mode:    "whitelist",
			Rules: []*conf.Authorization_Rule{
				{
					Name:        "admin",
					Hosts:       []string{"app.example.com"},
					PathMatch:   "prefix",
					Paths:       []string{"/admin/"},
					Methods:     []string{"GET"},
					AllowGroups: []string{"admin"},
				},
				{
					Name:       "ops",
					Hosts:      []string{"app.example.com"},
					PathMatch:  "wildcard",
					Paths:      []string{"~ ^/ops/[^/]+/dashboard$"},
					Methods:    []string{"GET"},
					AllowUsers: []string{"alice"},
				},
			},
		},
	}
}

type fakeUserRepo struct {
	users     map[string]*User
	whitelist map[string]bool
}

func (r *fakeUserRepo) FindByUsername(_ context.Context, username string) (*User, error) {
	u, ok := r.users[username]
	if !ok {
		return nil, ErrInvalidCredentials
	}
	cp := *u
	cp.Groups = append([]string(nil), u.Groups...)
	return &cp, nil
}

func (r *fakeUserRepo) IsWhitelisted(username string) bool {
	return r.whitelist[username]
}

type fakeSessionRepo struct {
	items   map[string]*Session
	lastTTL time.Duration
}

func newFakeSessionRepo() *fakeSessionRepo {
	return &fakeSessionRepo{items: map[string]*Session{}}
}

func (r *fakeSessionRepo) Save(_ context.Context, sessionID string, session *Session, ttl time.Duration) error {
	r.items[session.Host+"|"+sessionID] = cloneSession(session)
	r.lastTTL = ttl
	return nil
}

func (r *fakeSessionRepo) Find(_ context.Context, host, sessionID string) (*Session, error) {
	s, ok := r.items[NormalizeHost(host)+"|"+sessionID]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return cloneSession(s), nil
}

func (r *fakeSessionRepo) Refresh(_ context.Context, sessionID string, session *Session, ttl time.Duration) error {
	r.items[session.Host+"|"+sessionID] = cloneSession(session)
	r.lastTTL = ttl
	return nil
}

func (r *fakeSessionRepo) Delete(_ context.Context, host, sessionID string) error {
	delete(r.items, NormalizeHost(host)+"|"+sessionID)
	return nil
}

func cloneSession(s *Session) *Session {
	cp := *s
	cp.Groups = append([]string(nil), s.Groups...)
	return &cp
}

type fakeFailureRepo struct {
	ipFailures   map[string]int
	userFailures map[string]int
	ipBans       map[string]bool
	userBans     map[string]bool
	cleared      bool
}

func newFakeFailureRepo() *fakeFailureRepo {
	return &fakeFailureRepo{
		ipFailures:   map[string]int{},
		userFailures: map[string]int{},
		ipBans:       map[string]bool{},
		userBans:     map[string]bool{},
	}
}

func (r *fakeFailureRepo) IsIPBanned(_ context.Context, ip string) (bool, error) {
	return r.ipBans[ip], nil
}

func (r *fakeFailureRepo) IsUserBanned(_ context.Context, username string) (bool, error) {
	return r.userBans[username], nil
}

func (r *fakeFailureRepo) IncrementIPFailure(_ context.Context, ip string, _ time.Duration) (int, error) {
	r.ipFailures[ip]++
	return r.ipFailures[ip], nil
}

func (r *fakeFailureRepo) IncrementUserFailure(_ context.Context, username string, _ time.Duration) (int, error) {
	r.userFailures[username]++
	return r.userFailures[username], nil
}

func (r *fakeFailureRepo) BanIP(_ context.Context, ip string, _ time.Duration) error {
	r.ipBans[ip] = true
	return nil
}

func (r *fakeFailureRepo) BanUser(_ context.Context, username string, _ time.Duration) error {
	r.userBans[username] = true
	return nil
}

func (r *fakeFailureRepo) ClearFailures(_ context.Context, ip, username string) error {
	delete(r.ipFailures, ip)
	delete(r.userFailures, username)
	r.cleared = true
	return nil
}

type fakeAuditRepo struct {
	events []*LoginFailureEvent
}

func (r *fakeAuditRepo) WriteLoginFailure(_ context.Context, event *LoginFailureEvent) error {
	cp := *event
	r.events = append(r.events, &cp)
	return nil
}
