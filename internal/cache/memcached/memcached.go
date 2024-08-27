package memcached

import (
	"fmt"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
)

// Cache implements distributed cache based on Memcached.
type Cache struct {
	duration int32
	mc       *memcache.Client
}

// New creates a new instance.
func New(ttl time.Duration, servers ...string) (*Cache, error) {
	mc := memcache.New(servers...)

	if err := mc.Ping(); err != nil {
		return nil, fmt.Errorf("can not connect to Memcached nodes: %w", err)
	}

	return &Cache{
		mc:       mc,
		duration: int32(ttl.Seconds()),
	}, nil
}

// Get retrieves a value from cache.
func (mc *Cache) Get(key string) (string, bool, error) {
	item, err := mc.mc.Get(key)
	if err != nil {
		if err == memcache.ErrCacheMiss {
			return "", false, nil
		}

		return "", false, fmt.Errorf("can not retrieve value from cache: %w", err)
	}

	return string(item.Value), true, nil
}

// Set stores a value in cache.
func (mc *Cache) Set(key, value string) error {
	if err := mc.mc.Set(&memcache.Item{
		Key:        key,
		Value:      []byte(value),
		Expiration: mc.duration,
	}); err != nil {
		return fmt.Errorf("can not store a record in cache: %w", err)
	}

	return nil
}
