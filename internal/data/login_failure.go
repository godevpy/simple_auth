package data

import (
	"context"
	"time"

	"simple_auth/internal/biz"
)

type loginFailureRepo struct {
	data *Data
}

func NewLoginFailureRepo(data *Data) biz.LoginFailureRepo {
	return &loginFailureRepo{data: data}
}

func (r *loginFailureRepo) IsIPBanned(ctx context.Context, ip string) (bool, error) {
	return r.exists(ctx, r.ipBanKey(ip))
}

func (r *loginFailureRepo) IsUserBanned(ctx context.Context, username string) (bool, error) {
	return r.exists(ctx, r.userBanKey(username))
}

func (r *loginFailureRepo) IncrementIPFailure(ctx context.Context, ip string, window time.Duration) (int, error) {
	return r.increment(ctx, r.ipFailKey(ip), window)
}

func (r *loginFailureRepo) IncrementUserFailure(ctx context.Context, username string, window time.Duration) (int, error) {
	return r.increment(ctx, r.userFailKey(username), window)
}

func (r *loginFailureRepo) BanIP(ctx context.Context, ip string, duration time.Duration) error {
	return r.data.rdb.Set(ctx, r.ipBanKey(ip), "1", duration).Err()
}

func (r *loginFailureRepo) BanUser(ctx context.Context, username string, duration time.Duration) error {
	return r.data.rdb.Set(ctx, r.userBanKey(username), "1", duration).Err()
}

func (r *loginFailureRepo) ClearFailures(ctx context.Context, ip, username string) error {
	return r.data.rdb.Del(ctx, r.ipFailKey(ip), r.userFailKey(username)).Err()
}

func (r *loginFailureRepo) exists(ctx context.Context, key string) (bool, error) {
	n, err := r.data.rdb.Exists(ctx, key).Result()
	return n > 0, err
}

func (r *loginFailureRepo) increment(ctx context.Context, key string, window time.Duration) (int, error) {
	n, err := r.data.rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if n == 1 && window > 0 {
		if err := r.data.rdb.Expire(ctx, key, window).Err(); err != nil {
			return 0, err
		}
	}
	return int(n), nil
}

func (r *loginFailureRepo) ipFailKey(ip string) string {
	return r.data.prefixed("login", "fail", "ip", hashPart(ip))
}

func (r *loginFailureRepo) userFailKey(username string) string {
	return r.data.prefixed("login", "fail", "user", hashPart(username))
}

func (r *loginFailureRepo) ipBanKey(ip string) string {
	return r.data.prefixed("login", "ban", "ip", hashPart(ip))
}

func (r *loginFailureRepo) userBanKey(username string) string {
	return r.data.prefixed("login", "ban", "user", hashPart(username))
}
