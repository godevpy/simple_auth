package data

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"simple_auth/internal/biz"

	"github.com/redis/go-redis/v9"
)

type sessionRepo struct {
	data *Data
}

func NewSessionRepo(data *Data) biz.SessionRepo {
	return &sessionRepo{data: data}
}

func (r *sessionRepo) Save(ctx context.Context, sessionID string, session *biz.Session, ttl time.Duration) error {
	if ttl <= 0 {
		return biz.ErrUnauthorized
	}
	return r.set(ctx, sessionID, session, ttl)
}

func (r *sessionRepo) Find(ctx context.Context, host, sessionID string) (*biz.Session, error) {
	raw, err := r.data.rdb.Get(ctx, r.key(host, sessionID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, biz.ErrSessionNotFound
		}
		return nil, err
	}
	var session biz.Session
	if err := json.Unmarshal(raw, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (r *sessionRepo) Refresh(ctx context.Context, sessionID string, session *biz.Session, ttl time.Duration) error {
	if ttl <= 0 {
		return r.Delete(ctx, session.Host, sessionID)
	}
	return r.set(ctx, sessionID, session, ttl)
}

func (r *sessionRepo) Delete(ctx context.Context, host, sessionID string) error {
	return r.data.rdb.Del(ctx, r.key(host, sessionID)).Err()
}

func (r *sessionRepo) set(ctx context.Context, sessionID string, session *biz.Session, ttl time.Duration) error {
	raw, err := json.Marshal(session)
	if err != nil {
		return err
	}
	return r.data.rdb.Set(ctx, r.key(session.Host, sessionID), raw, ttl).Err()
}

func (r *sessionRepo) key(host, sessionID string) string {
	return r.data.prefixed("session", hashPart(biz.NormalizeHost(host)), biz.HashToken(sessionID))
}

func hashPart(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
