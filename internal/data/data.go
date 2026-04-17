package data

import (
	"context"
	"simple_auth/internal/biz"
	"simple_auth/internal/conf"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/wire"
	"github.com/redis/go-redis/v9"
)

// ProviderSet is data providers.
var ProviderSet = wire.NewSet(
	NewData,
	NewUserRepo,
	NewSessionRepo,
	NewLoginFailureRepo,
	NewAuditRepo,
	NewReadinessRepo,
)

// Data .
type Data struct {
	rdb       *redis.Client
	keyPrefix string
}

// NewData .
func NewData(c *conf.Bootstrap) (*Data, func(), error) {
	redisConf := c.GetData().GetRedis()
	network := redisConf.GetNetwork()
	if network == "" {
		network = "tcp"
	}
	addr := redisConf.GetAddr()
	if addr == "" {
		addr = "127.0.0.1:6379"
	}
	keyPrefix := redisConf.GetKeyPrefix()
	if keyPrefix == "" {
		keyPrefix = "auth"
	}
	opts := &redis.Options{
		Network:  network,
		Addr:     addr,
		Username: redisConf.GetUsername(),
		Password: redisConf.GetPassword(),
		DB:       int(redisConf.GetDb()),
	}
	if redisConf.GetReadTimeout() != nil {
		opts.ReadTimeout = redisConf.GetReadTimeout().AsDuration()
	}
	if redisConf.GetWriteTimeout() != nil {
		opts.WriteTimeout = redisConf.GetWriteTimeout().AsDuration()
	}
	rdb := redis.NewClient(opts)
	cleanup := func() {
		log.Info("closing the data resources")
		_ = rdb.Close()
	}
	return &Data{rdb: rdb, keyPrefix: keyPrefix}, cleanup, nil
}

func (d *Data) prefixed(parts ...string) string {
	key := d.keyPrefix
	for _, p := range parts {
		key += ":" + p
	}
	return key
}

type readinessRepo struct {
	data *Data
}

func NewReadinessRepo(data *Data) biz.ReadinessRepo {
	return &readinessRepo{data: data}
}

func (r *readinessRepo) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return r.data.rdb.Ping(ctx).Err()
}
