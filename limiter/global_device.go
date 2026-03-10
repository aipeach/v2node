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

	deviceSnapshotMu sync.RWMutex
	deviceSnapshot   map[string]*deviceSnapshotEntry // key: uid:limit

	dynamicSnapshotMu sync.RWMutex
	dynamicSnapshot   map[int]dynamicSyncCacheEntry // key: uid

	deviceDirty sync.Map // key: uid:limit:ip, value: globalDeviceCheckTask

	stopCh   chan struct{}
	stopOnce sync.Once
}

type deviceSnapshotEntry struct {
	IPs      map[string]struct{}
	ExpireAt int64
}

type dynamicSyncCacheEntry struct {
	Limit    int
	ExpireAt int64
	Found    bool
}

type globalDeviceCheckTask struct {
	UID         int
	DeviceLimit int
	IP          string
}

var globalDeviceLimitLock sync.RWMutex
var globalDeviceLimit *globalDeviceLimitRuntime

const (
	globalRedisSyncInterval = 30 * time.Second
	globalRedisScanCount    = 512
)

func SetGlobalDeviceLimitConfig(cfg GlobalDeviceLimitConfig) error {
	cfg = normalizeGlobalDeviceLimitConfig(cfg)

	globalDeviceLimitLock.Lock()
	defer globalDeviceLimitLock.Unlock()

	if globalDeviceLimit != nil {
		globalDeviceLimit.close()
		globalDeviceLimit = nil
	}

	if !cfg.Enable && !cfg.EnableDynamicSpeedLimit {
		return nil
	}
	if cfg.RedisAddr == "" {
		return fmt.Errorf("global redis limit is enabled but RedisAddr is empty")
	}

	runtime := &globalDeviceLimitRuntime{
		config: cfg,
		client: redis.NewClient(&redis.Options{
			Network:  cfg.RedisNetwork,
			Addr:     cfg.RedisAddr,
			Username: cfg.RedisUsername,
			Password: cfg.RedisPassword,
			DB:       cfg.RedisDB,
		}),
		deviceSnapshot:  make(map[string]*deviceSnapshotEntry),
		dynamicSnapshot: make(map[int]dynamicSyncCacheEntry),
	}

	// Startup warmup: load Redis snapshot into memory first.
	if err := runtime.syncAllFromRedis(); err != nil {
		log.WithError(err).Warn("initial global redis snapshot sync failed, continue with in-memory state")
	}
	runtime.startSyncLoop()
	globalDeviceLimit = runtime
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
	if uid <= 0 || deviceLimit <= 0 || ip == "" {
		return false
	}

	globalDeviceLimitLock.RLock()
	runtime := globalDeviceLimit
	globalDeviceLimitLock.RUnlock()
	if runtime == nil || runtime.client == nil || !runtime.config.Enable {
		return false
	}

	now := time.Now().Unix()
	stateKey := globalDeviceSnapshotKey(uid, deviceLimit)

	runtime.deviceSnapshotMu.Lock()
	entry, ok := runtime.deviceSnapshot[stateKey]
	if !ok || entry == nil {
		entry = &deviceSnapshotEntry{
			IPs:      make(map[string]struct{}),
			ExpireAt: now + int64(runtime.config.Expiry),
		}
		runtime.deviceSnapshot[stateKey] = entry
	}
	if entry.ExpireAt > 0 && entry.ExpireAt <= now {
		entry.IPs = make(map[string]struct{})
		entry.ExpireAt = now + int64(runtime.config.Expiry)
	}
	if _, exists := entry.IPs[ip]; exists {
		runtime.deviceSnapshotMu.Unlock()
		return false
	}
	if len(entry.IPs) >= deviceLimit {
		runtime.deviceSnapshotMu.Unlock()
		return true
	}
	entry.IPs[ip] = struct{}{}
	if entry.ExpireAt <= now {
		entry.ExpireAt = now + int64(runtime.config.Expiry)
	}
	runtime.deviceSnapshotMu.Unlock()

	// Async write-behind: batch flush every sync interval, never block hot path.
	runtime.enqueueDeviceDirty(uid, deviceLimit, ip)
	return false
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
	ctx, cancel := runtime.newRedisContext()
	defer cancel()

	_, err := runtime.client.Pipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.HSet(ctx, key, "limit", limit, "expire", expire.Unix())
		pipe.Expire(ctx, key, ttl)
		return nil
	})
	if err != nil {
		return fmt.Errorf("set dynamic speed limit to redis failed: %w", err)
	}

	cacheDynamicSync(runtime, uid, dynamicSyncCacheEntry{
		Limit:    limit,
		ExpireAt: expire.Unix(),
		Found:    true,
	})
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

	runtime.dynamicSnapshotMu.RLock()
	entry, ok := runtime.dynamicSnapshot[uid]
	runtime.dynamicSnapshotMu.RUnlock()
	if !ok || !entry.Found || entry.Limit <= 0 || entry.ExpireAt <= time.Now().Unix() {
		return false
	}

	changed := false
	if info.DynamicSpeedLimit != entry.Limit {
		info.DynamicSpeedLimit = entry.Limit
		changed = true
	}
	if info.ExpireTime != entry.ExpireAt {
		info.ExpireTime = entry.ExpireAt
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

func globalDeviceAllowCacheKey(uid, deviceLimit int, ip string) string {
	return fmt.Sprintf("%d:%d:%s", uid, deviceLimit, ip)
}

func globalDeviceSnapshotKey(uid, deviceLimit int) string {
	return fmt.Sprintf("%d:%d", uid, deviceLimit)
}

func parseGlobalDeviceLimitKey(key string) (uid, deviceLimit int, ok bool) {
	parts := strings.Split(key, ":")
	if len(parts) != 5 || parts[0] != "v2node" || parts[1] != "global-device" || parts[2] != "uid" {
		return 0, 0, false
	}
	uid, errUID := strconv.Atoi(parts[3])
	deviceLimit, errLimit := strconv.Atoi(parts[4])
	if errUID != nil || errLimit != nil {
		return 0, 0, false
	}
	return uid, deviceLimit, true
}

func parseGlobalDynamicSpeedLimitKey(key string) (uid int, ok bool) {
	parts := strings.Split(key, ":")
	if len(parts) != 4 || parts[0] != "v2node" || parts[1] != "global-dy-limit" || parts[2] != "uid" {
		return 0, false
	}
	uid, err := strconv.Atoi(parts[3])
	if err != nil {
		return 0, false
	}
	return uid, true
}

func (r *globalDeviceLimitRuntime) startSyncLoop() {
	r.stopCh = make(chan struct{})
	go r.syncLoop()
}

func (r *globalDeviceLimitRuntime) syncLoop() {
	ticker := time.NewTicker(globalRedisSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			if err := r.syncAllFromRedis(); err != nil {
				log.WithError(err).Warn("periodic global redis snapshot sync failed")
			}
		}
	}
}

func (r *globalDeviceLimitRuntime) syncAllFromRedis() error {
	if r == nil || r.client == nil {
		return nil
	}

	var errs []error
	if r.config.Enable {
		if err := r.syncDeviceSnapshotFromRedis(); err != nil {
			errs = append(errs, err)
		}
	}
	if r.config.EnableDynamicSpeedLimit {
		if err := r.syncDynamicSnapshotFromRedis(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("sync global redis snapshot failed: %v", errs)
}

func (r *globalDeviceLimitRuntime) syncDeviceSnapshotFromRedis() error {
	if err := r.flushDeviceDirtyToRedis(); err != nil {
		return err
	}
	snapshot, err := r.loadDeviceSnapshotFromRedis()
	if err != nil {
		return err
	}
	r.deviceSnapshotMu.Lock()
	r.deviceSnapshot = snapshot
	r.deviceSnapshotMu.Unlock()
	return nil
}

func (r *globalDeviceLimitRuntime) syncDynamicSnapshotFromRedis() error {
	snapshot, err := r.loadDynamicSnapshotFromRedis()
	if err != nil {
		return err
	}
	r.dynamicSnapshotMu.Lock()
	r.dynamicSnapshot = snapshot
	r.dynamicSnapshotMu.Unlock()
	return nil
}

func (r *globalDeviceLimitRuntime) loadDeviceSnapshotFromRedis() (map[string]*deviceSnapshotEntry, error) {
	snapshot := make(map[string]*deviceSnapshotEntry)
	var cursor uint64
	for {
		ctx, cancel := r.newRedisContext()
		keys, next, err := r.client.Scan(ctx, cursor, "v2node:global-device:uid:*", globalRedisScanCount).Result()
		cancel()
		if err != nil {
			return nil, fmt.Errorf("scan global device keys failed: %w", err)
		}

		if len(keys) > 0 {
			batch, err := r.loadDeviceSnapshotBatch(keys)
			if err != nil {
				return nil, err
			}
			for k, v := range batch {
				snapshot[k] = v
			}
		}

		if next == 0 {
			break
		}
		cursor = next
	}
	return snapshot, nil
}

func (r *globalDeviceLimitRuntime) loadDeviceSnapshotBatch(keys []string) (map[string]*deviceSnapshotEntry, error) {
	ctx, cancel := r.newRedisContext()
	defer cancel()

	pipe := r.client.Pipeline()
	hkeysCmd := make([]*redis.StringSliceCmd, len(keys))
	ttlCmd := make([]*redis.DurationCmd, len(keys))
	for i, key := range keys {
		hkeysCmd[i] = pipe.HKeys(ctx, key)
		ttlCmd[i] = pipe.TTL(ctx, key)
	}
	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("load global device snapshot batch failed: %w", err)
	}

	nowUnix := time.Now().Unix()
	fallbackTTL := int64(r.config.Expiry)
	if fallbackTTL <= 0 {
		fallbackTTL = 60
	}

	batch := make(map[string]*deviceSnapshotEntry, len(keys))
	for i, key := range keys {
		uid, deviceLimit, ok := parseGlobalDeviceLimitKey(key)
		if !ok || uid <= 0 || deviceLimit <= 0 {
			continue
		}
		ips, cmdErr := hkeysCmd[i].Result()
		if cmdErr != nil && cmdErr != redis.Nil {
			continue
		}
		if len(ips) == 0 {
			continue
		}

		entry := &deviceSnapshotEntry{
			IPs:      make(map[string]struct{}, len(ips)),
			ExpireAt: ttlToExpireAt(ttlCmd[i].Val(), nowUnix, fallbackTTL),
		}
		for _, ip := range ips {
			if ip != "" {
				entry.IPs[ip] = struct{}{}
			}
		}
		if len(entry.IPs) == 0 {
			continue
		}
		batch[globalDeviceSnapshotKey(uid, deviceLimit)] = entry
	}
	return batch, nil
}

func (r *globalDeviceLimitRuntime) loadDynamicSnapshotFromRedis() (map[int]dynamicSyncCacheEntry, error) {
	snapshot := make(map[int]dynamicSyncCacheEntry)
	var cursor uint64
	for {
		ctx, cancel := r.newRedisContext()
		keys, next, err := r.client.Scan(ctx, cursor, "v2node:global-dy-limit:uid:*", globalRedisScanCount).Result()
		cancel()
		if err != nil {
			return nil, fmt.Errorf("scan global dynamic limit keys failed: %w", err)
		}

		if len(keys) > 0 {
			batch, err := r.loadDynamicSnapshotBatch(keys)
			if err != nil {
				return nil, err
			}
			for uid, entry := range batch {
				snapshot[uid] = entry
			}
		}

		if next == 0 {
			break
		}
		cursor = next
	}
	return snapshot, nil
}

func (r *globalDeviceLimitRuntime) loadDynamicSnapshotBatch(keys []string) (map[int]dynamicSyncCacheEntry, error) {
	ctx, cancel := r.newRedisContext()
	defer cancel()

	pipe := r.client.Pipeline()
	hgetCmd := make([]*redis.MapStringStringCmd, len(keys))
	for i, key := range keys {
		hgetCmd[i] = pipe.HGetAll(ctx, key)
	}
	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("load global dynamic snapshot batch failed: %w", err)
	}

	nowUnix := time.Now().Unix()
	batch := make(map[int]dynamicSyncCacheEntry, len(keys))
	for i, key := range keys {
		uid, ok := parseGlobalDynamicSpeedLimitKey(key)
		if !ok || uid <= 0 {
			continue
		}
		values, cmdErr := hgetCmd[i].Result()
		if cmdErr != nil && cmdErr != redis.Nil {
			continue
		}
		if len(values) == 0 {
			continue
		}
		limit, limitErr := strconv.Atoi(strings.TrimSpace(values["limit"]))
		expireUnix, expireErr := strconv.ParseInt(strings.TrimSpace(values["expire"]), 10, 64)
		if limitErr != nil || expireErr != nil || limit <= 0 || expireUnix <= nowUnix {
			continue
		}
		batch[uid] = dynamicSyncCacheEntry{
			Limit:    limit,
			ExpireAt: expireUnix,
			Found:    true,
		}
	}
	return batch, nil
}

func (r *globalDeviceLimitRuntime) flushDeviceDirtyToRedis() error {
	tasks := make([]globalDeviceCheckTask, 0)
	r.deviceDirty.Range(func(key, value interface{}) bool {
		if task, ok := value.(globalDeviceCheckTask); ok {
			tasks = append(tasks, task)
		}
		r.deviceDirty.Delete(key)
		return true
	})
	if len(tasks) == 0 {
		return nil
	}

	ctx, cancel := r.newRedisContext()
	defer cancel()

	ttl := time.Duration(r.config.Expiry) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}

	pipe := r.client.Pipeline()
	for _, task := range tasks {
		key := buildGlobalDeviceLimitKey(task.UID, task.DeviceLimit)
		pipe.HSet(ctx, key, task.IP, task.UID)
		pipe.Expire(ctx, key, ttl)
	}
	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		for _, task := range tasks {
			r.enqueueDeviceDirty(task.UID, task.DeviceLimit, task.IP)
		}
		return fmt.Errorf("flush global device dirty tasks failed: %w", err)
	}
	return nil
}

func (r *globalDeviceLimitRuntime) enqueueDeviceDirty(uid, deviceLimit int, ip string) {
	key := globalDeviceAllowCacheKey(uid, deviceLimit, ip)
	r.deviceDirty.Store(key, globalDeviceCheckTask{
		UID:         uid,
		DeviceLimit: deviceLimit,
		IP:          ip,
	})
}

func (r *globalDeviceLimitRuntime) newRedisContext() (context.Context, context.CancelFunc) {
	timeout := time.Duration(r.config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return context.WithTimeout(context.Background(), timeout)
}

func ttlToExpireAt(ttl time.Duration, nowUnix int64, fallbackSeconds int64) int64 {
	if ttl > 0 {
		seconds := int64(ttl / time.Second)
		if seconds <= 0 {
			seconds = 1
		}
		return nowUnix + seconds
	}
	if fallbackSeconds <= 0 {
		fallbackSeconds = 60
	}
	return nowUnix + fallbackSeconds
}

func cacheDynamicSync(runtime *globalDeviceLimitRuntime, uid int, entry dynamicSyncCacheEntry) {
	runtime.dynamicSnapshotMu.Lock()
	if runtime.dynamicSnapshot == nil {
		runtime.dynamicSnapshot = make(map[int]dynamicSyncCacheEntry)
	}
	runtime.dynamicSnapshot[uid] = entry
	runtime.dynamicSnapshotMu.Unlock()
}

func (r *globalDeviceLimitRuntime) close() {
	r.stopOnce.Do(func() {
		if r.stopCh != nil {
			close(r.stopCh)
		}
	})
	if r.client != nil {
		_ = r.client.Close()
	}
}
