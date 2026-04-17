package biz

import (
	"net"
	"net/url"
	"regexp"
	"strings"

	"simple_auth/internal/conf"
)

type AuthorizationInput struct {
	Host   string
	URI    string
	Method string
	User   *User
}

type compiledRule struct {
	name         string
	hosts        map[string]struct{}
	pathMatch    string
	paths        []string
	regexps      []*regexp.Regexp
	methods      map[string]struct{}
	allowGroups  map[string]struct{}
	allowUsers   map[string]struct{}
	allowUserIDs map[string]struct{}
}

type AuthorizationUsecase struct {
	enabled bool
	rules   []compiledRule
}

func NewAuthorizationUsecase(c *conf.Bootstrap) (*AuthorizationUsecase, error) {
	az := &AuthorizationUsecase{}
	if c == nil || c.GetAuthorization() == nil {
		return az, nil
	}
	cfg := c.GetAuthorization()
	az.enabled = cfg.GetEnabled()
	for _, r := range cfg.GetRules() {
		rule := compiledRule{
			name:         r.GetName(),
			hosts:        stringSet(normalizeHosts(r.GetHosts())),
			pathMatch:    strings.ToLower(strings.TrimSpace(r.GetPathMatch())),
			paths:        append([]string(nil), r.GetPaths()...),
			methods:      stringSet(upperStrings(r.GetMethods())),
			allowGroups:  stringSet(r.GetAllowGroups()),
			allowUsers:   stringSet(r.GetAllowUsers()),
			allowUserIDs: stringSet(r.GetAllowUserIds()),
		}
		if rule.pathMatch == "" {
			rule.pathMatch = "prefix"
		}
		if rule.pathMatch == "wildcard" {
			for _, p := range rule.paths {
				pattern := strings.TrimSpace(p)
				pattern = strings.TrimSpace(strings.TrimPrefix(pattern, "~"))
				re, err := regexp.Compile(pattern)
				if err != nil {
					return nil, err
				}
				rule.regexps = append(rule.regexps, re)
			}
		}
		az.rules = append(az.rules, rule)
	}
	return az, nil
}

func (uc *AuthorizationUsecase) Allow(in AuthorizationInput) bool {
	if uc == nil || !uc.enabled {
		return true
	}
	host := NormalizeHost(in.Host)
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	requestPath := requestPath(in.URI)
	for _, rule := range uc.rules {
		if !rule.matchHost(host) || !rule.matchMethod(method) || !rule.matchPath(requestPath) {
			continue
		}
		return rule.matchUser(in.User)
	}
	return false
}

func (r compiledRule) matchHost(host string) bool {
	if len(r.hosts) == 0 {
		return true
	}
	_, ok := r.hosts[host]
	return ok
}

func (r compiledRule) matchMethod(method string) bool {
	if len(r.methods) == 0 {
		return true
	}
	_, ok := r.methods[method]
	return ok
}

func (r compiledRule) matchPath(path string) bool {
	if len(r.paths) == 0 && len(r.regexps) == 0 {
		return true
	}
	switch r.pathMatch {
	case "wildcard":
		for _, re := range r.regexps {
			if re.MatchString(path) {
				return true
			}
		}
	default:
		for _, prefix := range r.paths {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
	}
	return false
}

func (r compiledRule) matchUser(user *User) bool {
	if user == nil {
		return false
	}
	if len(r.allowGroups) == 0 && len(r.allowUsers) == 0 && len(r.allowUserIDs) == 0 {
		return true
	}
	if _, ok := r.allowUsers[user.Username]; ok {
		return true
	}
	if _, ok := r.allowUserIDs[user.ID]; ok {
		return true
	}
	for _, g := range user.Groups {
		if _, ok := r.allowGroups[g]; ok {
			return true
		}
	}
	return false
}

func requestPath(rawURI string) string {
	if rawURI == "" {
		return "/"
	}
	u, err := url.ParseRequestURI(rawURI)
	if err != nil {
		if i := strings.IndexByte(rawURI, '?'); i >= 0 {
			rawURI = rawURI[:i]
		}
		if rawURI == "" {
			return "/"
		}
		return rawURI
	}
	if u.Path == "" {
		return "/"
	}
	return u.Path
}

func NormalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	if i := strings.LastIndex(host, ":"); i > -1 && !strings.Contains(host[i+1:], "]") {
		withoutPort := host[:i]
		if withoutPort != "" && !strings.Contains(withoutPort, ":") {
			return withoutPort
		}
	}
	return strings.Trim(host, "[]")
}

func normalizeHosts(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if h := NormalizeHost(v); h != "" {
			out = append(out, h)
		}
	}
	return out
}

func upperStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if s := strings.ToUpper(strings.TrimSpace(v)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			set[s] = struct{}{}
		}
	}
	return set
}
