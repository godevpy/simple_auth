package data

import (
	"context"
	"strings"

	"simple_auth/internal/biz"
	"simple_auth/internal/conf"
)

type userConfigRepo struct {
	users     map[string]*biz.User
	whitelist map[string]struct{}
}

func NewUserRepo(c *conf.Bootstrap) biz.UserRepo {
	repo := &userConfigRepo{
		users:     make(map[string]*biz.User),
		whitelist: make(map[string]struct{}),
	}
	for _, u := range c.GetUsers() {
		user := &biz.User{
			ID:           u.GetId(),
			Username:     u.GetUsername(),
			DisplayName:  u.GetDisplayName(),
			PasswordHash: u.GetPasswordHash(),
			Groups:       append([]string(nil), u.GetGroups()...),
		}
		repo.users[user.Username] = user
	}
	for _, username := range c.GetSecurity().GetLoginFailure().GetUserWhitelist() {
		if username = strings.TrimSpace(username); username != "" {
			repo.whitelist[username] = struct{}{}
		}
	}
	return repo
}

func (r *userConfigRepo) FindByUsername(_ context.Context, username string) (*biz.User, error) {
	user, ok := r.users[strings.TrimSpace(username)]
	if !ok {
		return nil, biz.ErrInvalidCredentials
	}
	cp := *user
	cp.Groups = append([]string(nil), user.Groups...)
	return &cp, nil
}

func (r *userConfigRepo) IsWhitelisted(username string) bool {
	_, ok := r.whitelist[strings.TrimSpace(username)]
	return ok
}
