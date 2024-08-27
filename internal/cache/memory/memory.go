package memory

import (
	"time"

	"github.com/criteo/haproxy-spoe-auth/internal/cache"
	expcache "github.com/go-pkgz/expirable-cache/v3"
)

// Cache in memory cache implementation.
type Cache struct {
	duration time.Duration
	cache    expcache.Cache[string, string]
}

var _ cache.PKCEVerifierCache = (*Cache)(nil)

// New creates a new cache instance.
func New(ttl time.Duration) *Cache {
	return &Cache{
		cache:    expcache.NewCache[string, string](),
		duration: ttl,
	}
}

// Get retrieves an element.
func (mc *Cache) Get(key string) (string, bool, error) {
	v, ok := mc.cache.Get(key)

	return v, ok, nil
}

// Set stores an element.
func (mc *Cache) Set(key, value string) error {
	mc.cache.Set(key, value, mc.duration)

	return nil
}
