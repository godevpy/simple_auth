package service

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"simple_auth/internal/biz"
	"simple_auth/internal/conf"

	"github.com/go-kratos/kratos/v2/log"
)

type AuthService struct {
	auth     *biz.AuthUsecase
	ready    biz.ReadinessRepo
	template *template.Template
	cfg      serviceConfig
	log      *log.Helper
}

type serviceConfig struct {
	CookieName      string
	CookieDomain    string
	SecureCookie    bool
	SameSite        http.SameSite
	AbsoluteTimeout time.Duration
}

func NewAuthService(auth *biz.AuthUsecase, ready biz.ReadinessRepo, c *conf.Bootstrap, logger log.Logger) (*AuthService, error) {
	if logger == nil {
		logger = log.DefaultLogger
	}
	loginPage := "templates/login.html"
	if c.GetTemplates().GetLoginPage() != "" {
		loginPage = c.GetTemplates().GetLoginPage()
	}
	tmpl, err := template.ParseFiles(loginPage)
	if err != nil {
		return nil, err
	}
	cfg := buildServiceConfig(c)
	helper := log.NewHelper(logger)
	helper.Infof("auth service initialized: login_template=%s cookie_name=%s secure_cookie=%t same_site=%s", loginPage, cfg.CookieName, cfg.SecureCookie, c.GetSession().GetSameSite())
	return &AuthService{
		auth:     auth,
		ready:    ready,
		template: tmpl,
		cfg:      cfg,
		log:      helper,
	}, nil
}

func buildServiceConfig(c *conf.Bootstrap) serviceConfig {
	cfg := serviceConfig{
		CookieName:      "auth_session",
		SecureCookie:    true,
		SameSite:        http.SameSiteLaxMode,
		AbsoluteTimeout: 24 * time.Hour,
	}
	if c == nil || c.GetSession() == nil {
		return cfg
	}
	s := c.GetSession()
	if s.GetCookieName() != "" {
		cfg.CookieName = s.GetCookieName()
	}
	cfg.CookieDomain = s.GetCookieDomain()
	cfg.SecureCookie = s.GetSecureCookie()
	cfg.SameSite = parseSameSite(s.GetSameSite())
	if s.GetAbsoluteTimeout() != nil && s.GetAbsoluteTimeout().AsDuration() > 0 {
		cfg.AbsoluteTimeout = s.GetAbsoluteTimeout().AsDuration()
	}
	return cfg
}

func (s *AuthService) LoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.log.Warnf("login page method not allowed: method=%s ip=%s", r.Method, clientIP(r))
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.log.Debugf("login page rendered: ip=%s redirect=%s", clientIP(r), sanitizeRedirect(r.URL.Query().Get("redirect")))
	s.renderLogin(w, http.StatusOK, sanitizeRedirect(r.URL.Query().Get("redirect")), "")
}

func (s *AuthService) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.log.Warnf("login method not allowed: method=%s ip=%s", r.Method, clientIP(r))
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		s.log.Warnf("login bad request: ip=%s error=%v", clientIP(r), err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	redirect := sanitizeRedirect(r.FormValue("redirect"))
	username := strings.TrimSpace(r.FormValue("username"))
	result, err := s.auth.Login(r.Context(), biz.LoginInput{
		Username:  username,
		Password:  r.FormValue("password"),
		Host:      originalHost(r),
		ClientIP:  clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		if errors.Is(err, biz.ErrInvalidCredentials) {
			s.log.Warnf("login response: status=401 username=%s ip=%s host=%s", username, clientIP(r), originalHost(r))
			s.renderLogin(w, http.StatusUnauthorized, redirect, "用户名或密码错误")
			return
		}
		s.log.Errorf("login failed: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, s.sessionCookie(result.SessionID, int(time.Until(result.Session.ExpiresAt).Seconds())))
	s.log.Infof("login response: status=302 username=%s user_id=%s ip=%s redirect=%s", result.Session.Username, result.Session.UserID, clientIP(r), redirect)
	http.Redirect(w, r, redirect, http.StatusFound)
}

func (s *AuthService) Verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.log.Warnf("verify method not allowed: method=%s ip=%s", r.Method, clientIP(r))
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie(s.cfg.CookieName)
	if err != nil || cookie.Value == "" {
		s.log.Debugf("verify response: status=401 reason=missing_cookie host=%s uri=%s method=%s ip=%s", originalHost(r), originalURI(r), originalMethod(r), clientIP(r))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	session, err := s.auth.Verify(r.Context(), biz.VerifyInput{
		SessionID: cookie.Value,
		Host:      originalHost(r),
		URI:       originalURI(r),
		Method:    originalMethod(r),
		ClientIP:  clientIP(r),
		UserAgent: r.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, biz.ErrUnauthorized):
			s.log.Debugf("verify response: status=401 host=%s uri=%s method=%s ip=%s", originalHost(r), originalURI(r), originalMethod(r), clientIP(r))
			w.WriteHeader(http.StatusUnauthorized)
		case errors.Is(err, biz.ErrForbidden):
			s.log.Warnf("verify response: status=403 host=%s uri=%s method=%s ip=%s", originalHost(r), originalURI(r), originalMethod(r), clientIP(r))
			w.WriteHeader(http.StatusForbidden)
		default:
			s.log.Errorf("verify failed: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}
	w.Header().Set("X-Auth-User", session.Username)
	w.Header().Set("X-Auth-User-ID", session.UserID)
	w.Header().Set("X-Auth-Groups", strings.Join(session.Groups, ","))
	s.log.Debugf("verify response: status=204 username=%s user_id=%s host=%s uri=%s method=%s", session.Username, session.UserID, originalHost(r), originalURI(r), originalMethod(r))
	w.WriteHeader(http.StatusNoContent)
}

func (s *AuthService) Logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.log.Warnf("logout method not allowed: method=%s ip=%s", r.Method, clientIP(r))
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if cookie, err := r.Cookie(s.cfg.CookieName); err == nil {
		if err := s.auth.Logout(r.Context(), originalHost(r), cookie.Value); err != nil {
			s.log.Errorf("logout failed: %v", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}
	http.SetCookie(w, s.clearCookie())
	s.log.Infof("logout response: status=302 host=%s ip=%s", originalHost(r), clientIP(r))
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *AuthService) Me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.log.Warnf("me method not allowed: method=%s ip=%s", r.Method, clientIP(r))
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie(s.cfg.CookieName)
	if err != nil || cookie.Value == "" {
		s.log.Debugf("me response: status=401 reason=missing_cookie host=%s ip=%s", originalHost(r), clientIP(r))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	session, err := s.auth.Me(r.Context(), originalHost(r), cookie.Value)
	if err != nil {
		s.log.Debugf("me response: status=401 host=%s ip=%s error=%v", originalHost(r), clientIP(r), err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	s.log.Debugf("me response: status=200 username=%s user_id=%s host=%s", session.Username, session.UserID, originalHost(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":      session.UserID,
		"username":     session.Username,
		"display_name": session.DisplayName,
		"groups":       session.Groups,
		"expires_at":   session.ExpiresAt,
	})
}

func (s *AuthService) Healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *AuthService) Readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.ready.Ping(ctx); err != nil {
		s.log.Errorf("readyz failed: redis unavailable: %v", err)
		http.Error(w, "redis unavailable", http.StatusServiceUnavailable)
		return
	}
	s.log.Debug("readyz ok")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *AuthService) renderLogin(w http.ResponseWriter, status int, redirect, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = s.template.Execute(w, map[string]string{
		"Redirect": redirect,
		"Message":  message,
	})
}

func (s *AuthService) sessionCookie(value string, maxAge int) *http.Cookie {
	if maxAge < 0 {
		maxAge = 0
	}
	return &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    value,
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookie,
		SameSite: s.cfg.SameSite,
	}
}

func (s *AuthService) clearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     s.cfg.CookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cfg.CookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookie,
		SameSite: s.cfg.SameSite,
	}
}

func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

func sanitizeRedirect(value string) string {
	if value == "" {
		return "/"
	}
	if strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "//") {
		return value
	}
	return "/"
}

func originalHost(r *http.Request) string {
	if h := r.Header.Get("X-Original-Host"); h != "" {
		return h
	}
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		return h
	}
	return r.Host
}

func originalURI(r *http.Request) string {
	if uri := r.Header.Get("X-Original-URI"); uri != "" {
		return uri
	}
	if r.URL != nil {
		return r.URL.RequestURI()
	}
	return "/"
}

func originalMethod(r *http.Request) string {
	if method := r.Header.Get("X-Original-Method"); method != "" {
		return method
	}
	return r.Method
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
