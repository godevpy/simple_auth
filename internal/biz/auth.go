package biz

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"simple_auth/internal/conf"

	"github.com/go-kratos/kratos/v2/log"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrSessionNotFound    = errors.New("session not found")
)

type User struct {
	ID           string
	Username     string
	DisplayName  string
	PasswordHash string
	Groups       []string
}

type Session struct {
	SessionIDHash string    `json:"session_id_hash"`
	UserID        string    `json:"user_id"`
	Username      string    `json:"username"`
	DisplayName   string    `json:"display_name"`
	Groups        []string  `json:"groups"`
	Host          string    `json:"host"`
	CreatedAt     time.Time `json:"created_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	ClientIP      string    `json:"client_ip"`
	UserAgent     string    `json:"user_agent"`
}

func (s *Session) User() *User {
	return &User{
		ID:          s.UserID,
		Username:    s.Username,
		DisplayName: s.DisplayName,
		Groups:      append([]string(nil), s.Groups...),
	}
}

type UserRepo interface {
	FindByUsername(context.Context, string) (*User, error)
	IsWhitelisted(string) bool
}

type SessionRepo interface {
	Save(context.Context, string, *Session, time.Duration) error
	Find(context.Context, string, string) (*Session, error)
	Refresh(context.Context, string, *Session, time.Duration) error
	Delete(context.Context, string, string) error
}

type LoginFailureRepo interface {
	IsIPBanned(context.Context, string) (bool, error)
	IsUserBanned(context.Context, string) (bool, error)
	IncrementIPFailure(context.Context, string, time.Duration) (int, error)
	IncrementUserFailure(context.Context, string, time.Duration) (int, error)
	BanIP(context.Context, string, time.Duration) error
	BanUser(context.Context, string, time.Duration) error
	ClearFailures(context.Context, string, string) error
}

type AuditRepo interface {
	WriteLoginFailure(context.Context, *LoginFailureEvent) error
}

type ReadinessRepo interface {
	Ping(context.Context) error
}

type LoginFailureEvent struct {
	Time                time.Time `json:"time"`
	IP                  string    `json:"ip"`
	Username            string    `json:"username"`
	UserAgent           string    `json:"user_agent"`
	Reason              string    `json:"reason"`
	BanResult           string    `json:"ban_result"`
	PasswordAttemptHMAC string    `json:"password_attempt_hmac,omitempty"`
}

type LoginInput struct {
	Username  string
	Password  string
	Host      string
	ClientIP  string
	UserAgent string
}

type LoginResult struct {
	SessionID string
	Session   *Session
}

type VerifyInput struct {
	SessionID string
	Host      string
	URI       string
	Method    string
	ClientIP  string
	UserAgent string
}

type AuthUsecase struct {
	users      UserRepo
	sessions   SessionRepo
	failures   LoginFailureRepo
	audit      AuditRepo
	authorizer *AuthorizationUsecase
	cfg        authConfig
	now        func() time.Time
	log        *log.Helper
}

type authConfig struct {
	CookieName                string
	IdleTimeout               time.Duration
	AbsoluteTimeout           time.Duration
	SlidingExpiration         bool
	MaxAttempts               int
	FailureWindow             time.Duration
	BanDuration               time.Duration
	BanIP                     bool
	BanUser                   bool
	UserWhitelistEnabled      bool
	BanIPOnNonWhitelistedUser bool
	PasswordAttemptAudit      string
	PasswordAttemptHMACSecret string
}

func NewAuthUsecase(
	users UserRepo,
	sessions SessionRepo,
	failures LoginFailureRepo,
	audit AuditRepo,
	authorizer *AuthorizationUsecase,
	c *conf.Bootstrap,
	logger log.Logger,
) *AuthUsecase {
	if logger == nil {
		logger = log.DefaultLogger
	}
	return &AuthUsecase{
		users:      users,
		sessions:   sessions,
		failures:   failures,
		audit:      audit,
		authorizer: authorizer,
		cfg:        buildAuthConfig(c),
		now:        time.Now,
		log:        log.NewHelper(logger),
	}
}

func buildAuthConfig(c *conf.Bootstrap) authConfig {
	cfg := authConfig{
		CookieName:                "auth_session",
		IdleTimeout:               30 * time.Minute,
		AbsoluteTimeout:           24 * time.Hour,
		SlidingExpiration:         true,
		MaxAttempts:               3,
		FailureWindow:             30 * time.Minute,
		BanDuration:               30 * time.Minute,
		BanIP:                     true,
		BanUser:                   true,
		UserWhitelistEnabled:      true,
		BanIPOnNonWhitelistedUser: true,
		PasswordAttemptAudit:      "hmac",
	}
	if c == nil {
		return cfg
	}
	if s := c.GetSession(); s != nil {
		if s.GetCookieName() != "" {
			cfg.CookieName = s.GetCookieName()
		}
		if s.GetIdleTimeout() != nil && s.GetIdleTimeout().AsDuration() > 0 {
			cfg.IdleTimeout = s.GetIdleTimeout().AsDuration()
		}
		if s.GetAbsoluteTimeout() != nil && s.GetAbsoluteTimeout().AsDuration() > 0 {
			cfg.AbsoluteTimeout = s.GetAbsoluteTimeout().AsDuration()
		}
		cfg.SlidingExpiration = s.GetSlidingExpiration()
	}
	if lf := c.GetSecurity().GetLoginFailure(); lf != nil {
		if lf.GetMaxAttempts() > 0 {
			cfg.MaxAttempts = int(lf.GetMaxAttempts())
		}
		if lf.GetWindow() != nil && lf.GetWindow().AsDuration() > 0 {
			cfg.FailureWindow = lf.GetWindow().AsDuration()
		}
		if lf.GetBanDuration() != nil && lf.GetBanDuration().AsDuration() > 0 {
			cfg.BanDuration = lf.GetBanDuration().AsDuration()
		}
		cfg.BanIP = lf.GetBanIp()
		cfg.BanUser = lf.GetBanUser()
		cfg.UserWhitelistEnabled = lf.GetUserWhitelistEnabled()
		cfg.BanIPOnNonWhitelistedUser = lf.GetBanIpOnNonWhitelistedUser()
		if lf.GetPasswordAttemptAudit() != "" {
			cfg.PasswordAttemptAudit = lf.GetPasswordAttemptAudit()
		}
		cfg.PasswordAttemptHMACSecret = lf.GetPasswordAttemptHmacSecret()
	}
	return cfg
}

func (uc *AuthUsecase) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	username := strings.TrimSpace(in.Username)
	clientIP := strings.TrimSpace(in.ClientIP)
	userAgent := in.UserAgent

	if banned, err := uc.failures.IsIPBanned(ctx, clientIP); err != nil {
		return nil, err
	} else if banned {
		_ = uc.auditFailure(ctx, in, "ip_banned", "none")
		return nil, ErrInvalidCredentials
	}
	if banned, err := uc.failures.IsUserBanned(ctx, username); err != nil {
		return nil, err
	} else if banned {
		_ = uc.auditFailure(ctx, in, "user_banned", "none")
		return nil, ErrInvalidCredentials
	}

	if uc.cfg.UserWhitelistEnabled && !uc.users.IsWhitelisted(username) {
		banResult := "none"
		if uc.cfg.BanIP && uc.cfg.BanIPOnNonWhitelistedUser {
			if err := uc.failures.BanIP(ctx, clientIP, uc.cfg.BanDuration); err != nil {
				return nil, err
			}
			banResult = "ip_banned"
		}
		_ = uc.auditFailure(ctx, in, "non_whitelisted_user", banResult)
		return nil, ErrInvalidCredentials
	}

	user, err := uc.users.FindByUsername(ctx, username)
	if err != nil {
		if recordErr := uc.recordCredentialFailure(ctx, in, "user_not_found"); recordErr != nil {
			return nil, recordErr
		}
		return nil, ErrInvalidCredentials
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(in.Password)); err != nil {
		if recordErr := uc.recordCredentialFailure(ctx, in, "bad_password"); recordErr != nil {
			return nil, recordErr
		}
		return nil, ErrInvalidCredentials
	}

	if err := uc.failures.ClearFailures(ctx, clientIP, username); err != nil {
		return nil, err
	}

	sessionID, err := newSessionID()
	if err != nil {
		return nil, err
	}
	now := uc.now().UTC()
	session := &Session{
		SessionIDHash: HashToken(sessionID),
		UserID:        user.ID,
		Username:      user.Username,
		DisplayName:   user.DisplayName,
		Groups:        append([]string(nil), user.Groups...),
		Host:          NormalizeHost(in.Host),
		CreatedAt:     now,
		LastSeenAt:    now,
		ExpiresAt:     now.Add(uc.cfg.AbsoluteTimeout),
		ClientIP:      clientIP,
		UserAgent:     userAgent,
	}
	if err := uc.sessions.Save(ctx, sessionID, session, uc.sessionTTL(now, session.ExpiresAt)); err != nil {
		return nil, err
	}
	return &LoginResult{SessionID: sessionID, Session: session}, nil
}

func (uc *AuthUsecase) Verify(ctx context.Context, in VerifyInput) (*Session, error) {
	if strings.TrimSpace(in.SessionID) == "" {
		return nil, ErrUnauthorized
	}
	session, err := uc.sessions.Find(ctx, in.Host, in.SessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	now := uc.now().UTC()
	if !session.ExpiresAt.After(now) {
		_ = uc.sessions.Delete(ctx, in.Host, in.SessionID)
		return nil, ErrUnauthorized
	}
	if !uc.authorizer.Allow(AuthorizationInput{
		Host:   in.Host,
		URI:    in.URI,
		Method: in.Method,
		User:   session.User(),
	}) {
		return nil, ErrForbidden
	}
	if uc.cfg.SlidingExpiration {
		session.LastSeenAt = now
		if err := uc.sessions.Refresh(ctx, in.SessionID, session, uc.sessionTTL(now, session.ExpiresAt)); err != nil {
			return nil, err
		}
	}
	return session, nil
}

func (uc *AuthUsecase) Logout(ctx context.Context, host, sessionID string) error {
	if strings.TrimSpace(sessionID) == "" {
		return nil
	}
	return uc.sessions.Delete(ctx, host, sessionID)
}

func (uc *AuthUsecase) Me(ctx context.Context, host, sessionID string) (*Session, error) {
	if strings.TrimSpace(sessionID) == "" {
		return nil, ErrUnauthorized
	}
	session, err := uc.sessions.Find(ctx, host, sessionID)
	if err != nil {
		if errors.Is(err, ErrSessionNotFound) {
			return nil, ErrUnauthorized
		}
		return nil, err
	}
	if !session.ExpiresAt.After(uc.now().UTC()) {
		_ = uc.sessions.Delete(ctx, host, sessionID)
		return nil, ErrUnauthorized
	}
	return session, nil
}

func (uc *AuthUsecase) recordCredentialFailure(ctx context.Context, in LoginInput, reason string) error {
	ipCount, err := uc.failures.IncrementIPFailure(ctx, in.ClientIP, uc.cfg.FailureWindow)
	if err != nil {
		return err
	}
	userCount, err := uc.failures.IncrementUserFailure(ctx, in.Username, uc.cfg.FailureWindow)
	if err != nil {
		return err
	}
	banResult := "none"
	if uc.cfg.BanIP && ipCount >= uc.cfg.MaxAttempts {
		if err := uc.failures.BanIP(ctx, in.ClientIP, uc.cfg.BanDuration); err != nil {
			return err
		}
		banResult = appendBanResult(banResult, "ip_banned")
	}
	if uc.cfg.BanUser && userCount >= uc.cfg.MaxAttempts {
		if err := uc.failures.BanUser(ctx, in.Username, uc.cfg.BanDuration); err != nil {
			return err
		}
		banResult = appendBanResult(banResult, "user_banned")
	}
	return uc.auditFailure(ctx, in, reason, banResult)
}

func (uc *AuthUsecase) auditFailure(ctx context.Context, in LoginInput, reason, banResult string) error {
	return uc.audit.WriteLoginFailure(ctx, &LoginFailureEvent{
		Time:                uc.now().UTC(),
		IP:                  in.ClientIP,
		Username:            strings.TrimSpace(in.Username),
		UserAgent:           in.UserAgent,
		Reason:              reason,
		BanResult:           banResult,
		PasswordAttemptHMAC: uc.passwordAttemptHMAC(in.Password),
	})
}

func (uc *AuthUsecase) passwordAttemptHMAC(password string) string {
	if strings.ToLower(uc.cfg.PasswordAttemptAudit) != "hmac" || uc.cfg.PasswordAttemptHMACSecret == "" {
		return ""
	}
	mac := hmac.New(sha256.New, []byte(uc.cfg.PasswordAttemptHMACSecret))
	_, _ = mac.Write([]byte(password))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (uc *AuthUsecase) sessionTTL(now, expiresAt time.Time) time.Duration {
	remaining := time.Until(expiresAt)
	if !now.IsZero() {
		remaining = expiresAt.Sub(now)
	}
	if remaining <= 0 {
		return 0
	}
	if uc.cfg.IdleTimeout <= 0 || remaining < uc.cfg.IdleTimeout {
		return remaining
	}
	return uc.cfg.IdleTimeout
}

func newSessionID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func appendBanResult(current, next string) string {
	if current == "" || current == "none" {
		return next
	}
	return current + "," + next
}
