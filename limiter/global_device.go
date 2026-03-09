package limiter

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

type GlobalDeviceLimitConfig struct {
	Enable                  bool
	EnableDynamicSpeedLimit bool
	RedisNetwork            string
	RedisAddr               string
	RedisUsername           string
	RedisPassword           string
	RedisDB                 int
	Timeout                 int
	Expiry                  int
}

type globalDeviceLimitRuntime struct {
	config GlobalDeviceLimitConfig
	client *redis.Client
}

var globalDeviceLimitLock sync.RWMutex
var globalDeviceLimit *globalDeviceLimitRuntime

var globalDeviceLimitScript = redis.NewScript(`
local key = KEYS[1]
local ip = ARGV[1]
local uid = ARGV[2]
local limit = tonumber(ARGV[3])
local expiry = tonumber(ARGV[4])

if limit == nil or limit <= 0 then
  return 0
end

if redis.call("HEXISTS", key, ip) == 1 then
  if expiry ~= nil and expiry > 0 then
    redis.call("EXPIRE", key, expiry)
  end
  return 0
end

local size = redis.call("HLEN", key)
if size >= limit then
  if expiry ~= nil and expiry > 0 then
    redis.call("EXPIRE", key, expiry)
  end
  return 1
end

redis.call("HSET", key, ip, uid)
if expiry ~= nil and expiry > 0 then
  redis.call("EXPIRE", key, expiry)
end
return 0
`)

func SetGlobalDeviceLimitConfig(cfg GlobalDeviceLimitConfig) error {
	cfg = normalizeGlobalDeviceLimitConfig(cfg)

	globalDeviceLimitLock.Lock()
	defer globalDeviceLimitLock.Unlock()

	if globalDeviceLimit != nil && globalDeviceLimit.client != nil {
		_ = globalDeviceLimit.client.Close()
		globalDeviceLimit = nil
	}

	if !cfg.Enable && !cfg.EnableDynamicSpeedLimit {
		return nil
	}
	if cfg.RedisAddr == "" {
		return fmt.Errorf("global redis limit is enabled but RedisAddr is empty")
	}

	globalDeviceLimit = &globalDeviceLimitRuntime{
		config: cfg,
		client: redis.NewClient(&redis.Options{
			Network:  cfg.RedisNetwork,
			Addr:     cfg.RedisAddr,
			Username: cfg.RedisUsername,
			Password: cfg.RedisPassword,
			DB:       cfg.RedisDB,
		}),
	}
	return nil
}

func normalizeGlobalDeviceLimitConfig(cfg GlobalDeviceLimitConfig) GlobalDeviceLimitConfig {
	cfg.RedisNetwork = strings.ToLower(strings.TrimSpace(cfg.RedisNetwork))
	if cfg.RedisNetwork == "" {
		cfg.RedisNetwork = "tcp"
	}
	cfg.RedisAddr = strings.TrimSpace(cfg.RedisAddr)
	cfg.RedisUsername = strings.TrimSpace(cfg.RedisUsername)
	if cfg.RedisDB < 0 {
		cfg.RedisDB = 0
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5
	}
	if cfg.Expiry <= 0 {
		cfg.Expiry = 60
	}
	return cfg
}

func checkGlobalDeviceLimit(uid, deviceLimit int, ip string) bool {
	if uid <= 0 || deviceLimit <= 0 {
		return false
	}

	globalDeviceLimitLock.RLock()
	runtime := globalDeviceLimit
	globalDeviceLimitLock.RUnlock()
	if runtime == nil || runtime.client == nil || !runtime.config.Enable {
		return false
	}

	key := buildGlobalDeviceLimitKey(uid, deviceLimit)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(runtime.config.Timeout)*time.Second)
	defer cancel()

	result, err := globalDeviceLimitScript.Run(
		ctx,
		runtime.client,
		[]string{key},
		ip,
		uid,
		deviceLimit,
		runtime.config.Expiry,
	).Int()
	if err != nil {
		log.WithFields(log.Fields{
			"uid": uid,
			"ip":  ip,
			"key": key,
		}).WithError(err).Warn("global device limit redis check failed, fallback to allow")
		return false
	}

	return result == 1
}

func SetGlobalDynamicSpeedLimitByUID(uid, limit int, expire time.Time) error {
	if uid <= 0 || limit <= 0 {
		return nil
	}

	globalDeviceLimitLock.RLock()
	runtime := globalDeviceLimit
	globalDeviceLimitLock.RUnlock()
	if runtime == nil || runtime.client == nil || !runtime.config.EnableDynamicSpeedLimit {
		return nil
	}

	ttl := time.Until(expire)
	if ttl <= 0 {
		return nil
	}
	key := buildGlobalDynamicSpeedLimitKey(uid)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(runtime.config.Timeout)*time.Second)
	defer cancel()

	_, err := runtime.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.HSet(ctx, key, "limit", limit, "expire", expire.Unix())
		pipe.Expire(ctx, key, ttl)
		return nil
	})
	if err != nil {
		return fmt.Errorf("set dynamic speed limit to redis failed: %w", err)
	}
	return nil
}

func syncGlobalDynamicSpeedLimit(uid int, info *UserLimitInfo) bool {
	if uid <= 0 || info == nil {
		return false
	}

	globalDeviceLimitLock.RLock()
	runtime := globalDeviceLimit
	globalDeviceLimitLock.RUnlock()
	if runtime == nil || runtime.client == nil || !runtime.config.EnableDynamicSpeedLimit {
		return false
	}

	key := buildGlobalDynamicSpeedLimitKey(uid)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(runtime.config.Timeout)*time.Second)
	defer cancel()

	m, err := runtime.client.HGetAll(ctx, key).Result()
	if err != nil {
		log.WithFields(log.Fields{
			"uid": uid,
			"key": key,
		}).WithError(err).Warn("global dynamic speed limit redis sync failed, fallback to local")
		return false
	}
	if len(m) == 0 {
		return false
	}

	limitStr, ok := m["limit"]
	if !ok {
		return false
	}
	expireStr, ok := m["expire"]
	if !ok {
		return false
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		return false
	}
	expireUnix, err := strconv.ParseInt(expireStr, 10, 64)
	if err != nil || expireUnix <= time.Now().Unix() {
		return false
	}

	changed := false
	if info.DynamicSpeedLimit != limit {
		info.DynamicSpeedLimit = limit
		changed = true
	}
	if info.ExpireTime != expireUnix {
		info.ExpireTime = expireUnix
		changed = true
	}
	return changed
}

func buildGlobalDeviceLimitKey(uid, deviceLimit int) string {
	return fmt.Sprintf("v2node:global-device:uid:%d:%d", uid, deviceLimit)
}

func buildGlobalDynamicSpeedLimitKey(uid int) string {
	return fmt.Sprintf("v2node:global-dy-limit:uid:%d", uid)
}
