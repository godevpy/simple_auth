package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"simple_auth/internal/biz"
	"simple_auth/internal/conf"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestAuthServiceVerifyStatuses(t *testing.T) {
	svc, sessions := newTestService(t)
	sessionID := "session-token"
	now := time.Now().UTC()
	if err := sessions.Save(context.Background(), sessionID, &biz.Session{
		SessionIDHash: biz.HashToken(sessionID),
		UserID:        "user-001",
		Username:      "alice",
		Groups:        []string{"admin"},
		Host:          "app.example.com",
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(time.Hour),
	}, time.Minute); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	missingCookie := httptest.NewRecorder()
	svc.Verify(missingCookie, httptest.NewRequest(http.MethodGet, "/auth/verify", nil))
	if missingCookie.Code != http.StatusUnauthorized {
		t.Fatalf("missing cookie status = %d", missingCookie.Code)
	}

	allowed := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	req.Header.Set("X-Original-Host", "app.example.com")
	req.Header.Set("X-Original-URI", "/admin/dashboard")
	req.Header.Set("X-Original-Method", "GET")
	svc.Verify(allowed, req)
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("allowed status = %d", allowed.Code)
	}

	forbidden := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
	req.AddCookie(&http.Cookie{Name: "auth_session", Value: sessionID})
	req.Header.Set("X-Original-Host", "app.example.com")
	req.Header.Set("X-Original-URI", "/unknown")
	req.Header.Set("X-Original-Method", "GET")
	svc.Verify(forbidden, req)
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("forbidden status = %d", forbidden.Code)
	}
}

func TestAuthServiceLoginSuccessAndFailure(t *testing.T) {
	svc, _ := newTestService(t)

	form := url.Values{}
	form.Set("username", "alice")
	form.Set("password", "secret")
	form.Set("redirect", "/admin/dashboard")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "app.example.com"
	w := httptest.NewRecorder()
	svc.Login(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("login success status = %d", w.Code)
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatal("expected login to set cookie")
	}
	if loc := w.Header().Get("Location"); loc != "/admin/dashboard" {
		t.Fatalf("redirect location = %q", loc)
	}

	form.Set("password", "wrong")
	req = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "app.example.com"
	w = httptest.NewRecorder()
	svc.Login(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login failure status = %d", w.Code)
	}
}

func newTestService(t *testing.T) (*AuthService, *serviceSessionRepo) {
	t.Helper()
	tpl := t.TempDir() + "/login.html"
	if err := osWriteFile(tpl, []byte(`{{.Message}}<form method="post"><input name="redirect" value="{{.Redirect}}"></form>`)); err != nil {
		t.Fatalf("write template: %v", err)
	}
	bc := serviceBootstrap(t, tpl)
	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword() error = %v", err)
	}
	users := &serviceUserRepo{
		users: map[string]*biz.User{
			"alice": {ID: "user-001", Username: "alice", PasswordHash: string(hash), Groups: []string{"admin"}},
		},
		whitelist: map[string]bool{"alice": true},
	}
	sessions := newServiceSessionRepo()
	failures := newServiceFailureRepo()
	audit := &serviceAuditRepo{}
	az, err := biz.NewAuthorizationUsecase(bc)
	if err != nil {
		t.Fatalf("NewAuthorizationUsecase() error = %v", err)
	}
	uc := biz.NewAuthUsecase(users, sessions, failures, audit, az, bc, nil)
	svc, err := NewAuthService(uc, serviceReadyRepo{}, bc, nil)
	if err != nil {
		t.Fatalf("NewAuthService() error = %v", err)
	}
	return svc, sessions
}

func serviceBootstrap(t *testing.T, loginTemplate string) *conf.Bootstrap {
	t.Helper()
	return &conf.Bootstrap{
		Templates: &conf.Templates{LoginPage: loginTemplate},
		Session: &conf.Session{
			CookieName:        "auth_session",
			IdleTimeout:       durationpb.New(30 * time.Minute),
			AbsoluteTimeout:   durationpb.New(24 * time.Hour),
			SlidingExpiration: true,
			SameSite:          "Lax",
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
			Rules: []*conf.Authorization_Rule{{
				Name:        "admin",
				Hosts:       []string{"app.example.com"},
				PathMatch:   "prefix",
				Paths:       []string{"/admin/"},
				Methods:     []string{"GET"},
				AllowGroups: []string{"admin"},
			}},
		},
	}
}

type serviceReadyRepo struct{}

func (serviceReadyRepo) Ping(context.Context) error { return nil }

type serviceUserRepo struct {
	users     map[string]*biz.User
	whitelist map[string]bool
}

func (r *serviceUserRepo) FindByUsername(_ context.Context, username string) (*biz.User, error) {
	u, ok := r.users[username]
	if !ok {
		return nil, biz.ErrInvalidCredentials
	}
	cp := *u
	cp.Groups = append([]string(nil), u.Groups...)
	return &cp, nil
}

func (r *serviceUserRepo) IsWhitelisted(username string) bool {
	return r.whitelist[username]
}

type serviceSessionRepo struct {
	items map[string]*biz.Session
}

func newServiceSessionRepo() *serviceSessionRepo {
	return &serviceSessionRepo{items: map[string]*biz.Session{}}
}

func (r *serviceSessionRepo) Save(_ context.Context, sessionID string, session *biz.Session, _ time.Duration) error {
	r.items[session.Host+"|"+sessionID] = cloneServiceSession(session)
	return nil
}

func (r *serviceSessionRepo) Find(_ context.Context, host, sessionID string) (*biz.Session, error) {
	s, ok := r.items[biz.NormalizeHost(host)+"|"+sessionID]
	if !ok {
		return nil, biz.ErrSessionNotFound
	}
	return cloneServiceSession(s), nil
}

func (r *serviceSessionRepo) Refresh(_ context.Context, sessionID string, session *biz.Session, _ time.Duration) error {
	r.items[session.Host+"|"+sessionID] = cloneServiceSession(session)
	return nil
}

func (r *serviceSessionRepo) Delete(_ context.Context, host, sessionID string) error {
	delete(r.items, biz.NormalizeHost(host)+"|"+sessionID)
	return nil
}

func cloneServiceSession(s *biz.Session) *biz.Session {
	cp := *s
	cp.Groups = append([]string(nil), s.Groups...)
	return &cp
}

type serviceFailureRepo struct {
	ipFailures   map[string]int
	userFailures map[string]int
	ipBans       map[string]bool
	userBans     map[string]bool
}

func newServiceFailureRepo() *serviceFailureRepo {
	return &serviceFailureRepo{
		ipFailures:   map[string]int{},
		userFailures: map[string]int{},
		ipBans:       map[string]bool{},
		userBans:     map[string]bool{},
	}
}

func (r *serviceFailureRepo) IsIPBanned(_ context.Context, ip string) (bool, error) {
	return r.ipBans[ip], nil
}

func (r *serviceFailureRepo) IsUserBanned(_ context.Context, username string) (bool, error) {
	return r.userBans[username], nil
}

func (r *serviceFailureRepo) IncrementIPFailure(_ context.Context, ip string, _ time.Duration) (int, error) {
	r.ipFailures[ip]++
	return r.ipFailures[ip], nil
}

func (r *serviceFailureRepo) IncrementUserFailure(_ context.Context, username string, _ time.Duration) (int, error) {
	r.userFailures[username]++
	return r.userFailures[username], nil
}

func (r *serviceFailureRepo) BanIP(_ context.Context, ip string, _ time.Duration) error {
	r.ipBans[ip] = true
	return nil
}

func (r *serviceFailureRepo) BanUser(_ context.Context, username string, _ time.Duration) error {
	r.userBans[username] = true
	return nil
}

func (r *serviceFailureRepo) ClearFailures(_ context.Context, ip, username string) error {
	delete(r.ipFailures, ip)
	delete(r.userFailures, username)
	return nil
}

type serviceAuditRepo struct{}

func (serviceAuditRepo) WriteLoginFailure(_ context.Context, _ *biz.LoginFailureEvent) error {
	return nil
}

func osWriteFile(name string, data []byte) error {
	return os.WriteFile(name, data, 0o600)
}
