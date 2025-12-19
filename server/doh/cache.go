package doh

import (
	"sync"
	"time"
)

// DNSCache DNS 缓存
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	response  *Response
	expiresAt time.Time
}

var (
	globalCache     *DNSCache
	globalCacheOnce sync.Once
)

// GetCache 获取全局 DNS 缓存
func GetCache() *DNSCache {
	globalCacheOnce.Do(func() {
		globalCache = &DNSCache{
			entries: make(map[string]*cacheEntry),
		}
		// 启动清理协程
		go globalCache.cleanupLoop()
	})
	return globalCache
}

// Get 从缓存获取
func (c *DNSCache) Get(key string) (*Response, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	// 检查是否过期
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.response, true
}

// Set 设置缓存
func (c *DNSCache) Set(key string, resp *Response, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 最小 TTL 60 秒，最大 TTL 1 小时
	if ttl < 60*time.Second {
		ttl = 60 * time.Second
	}
	if ttl > time.Hour {
		ttl = time.Hour
	}

	c.entries[key] = &cacheEntry{
		response:  resp,
		expiresAt: time.Now().Add(ttl),
	}
}

// cleanupLoop 定期清理过期条目
func (c *DNSCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.cleanup()
	}
}

// cleanup 清理过期条目
func (c *DNSCache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

// Size 返回缓存大小
func (c *DNSCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

