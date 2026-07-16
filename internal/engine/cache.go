package engine

import (
	"container/list"
	"sync"
	"time"
)

type cacheEntry struct {
	key   string
	value any
	ts    time.Time
}

type LRUCache struct {
	mu       sync.Mutex
	store    map[string]*list.Element
	lru      *list.List
	maxSize  int
	ttl      time.Duration
}

func NewLRUCache(maxSize int, ttl time.Duration) *LRUCache {
	return &LRUCache{
		store:   make(map[string]*list.Element, maxSize),
		lru:     list.New(),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func (c *LRUCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.store[key]
	if !ok {
		return nil, false
	}
	entry := el.Value.(*cacheEntry)
	if time.Since(entry.ts) > c.ttl {
		c.lru.Remove(el)
		delete(c.store, key)
		return nil, false
	}
	c.lru.MoveToFront(el)
	return entry.value, true
}

func (c *LRUCache) Set(key string, value any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.store[key]; ok {
		c.lru.Remove(el)
	} else if len(c.store) >= c.maxSize {
		back := c.lru.Back()
		if back != nil {
			c.lru.Remove(back)
			delete(c.store, back.Value.(*cacheEntry).key)
		}
	}
	entry := &cacheEntry{key: key, value: value, ts: time.Now()}
	c.store[key] = c.lru.PushFront(entry)
}

func (c *LRUCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store = make(map[string]*list.Element, c.maxSize)
	c.lru = list.New()
}

func (c *LRUCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.store)
}
