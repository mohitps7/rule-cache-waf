package cache

import (
	"container/list"
	"sync"
)

type item[T any] struct {
	key     string
	value   T
	element *list.Element
}

type LRU[T any] struct {
	sync.Mutex
	items       map[string]*item[T]
	keyList     *list.List
	maxSize     int
	currentSize int
}

func NewLru[T any](limit int) *LRU[T] {
	return &LRU[T]{
		items:   make(map[string]*item[T]),
		keyList: list.New(),
		maxSize: limit,
	}
}

func (lru *LRU[T]) MaxStorage() int {
	lru.Lock()
	defer lru.Unlock()
	return lru.maxSize
}

func (lru *LRU[T]) RemainingStorage() int {
	lru.Lock()
	defer lru.Unlock()
	return lru.maxSize - lru.currentSize
}

func (lru *LRU[T]) Get(key string) (value T, ok bool) {
	lru.Lock()
	defer lru.Unlock()

	if itm, ok := lru.items[key]; ok {
		lru.keyList.MoveToFront(itm.element)
		return itm.value, true
	}

	var defaultValue T
	return defaultValue, false
}

func (lru *LRU[T]) Remove(key string) (value T, ok bool) {
	lru.Lock()
	defer lru.Unlock()

	if itm, found := lru.items[key]; found {
		delete(lru.items, key)
		lru.keyList.Remove(itm.element)
		lru.currentSize -= 1
		return itm.value, true
	}

	var defaultValue T
	return defaultValue, false
}

func (lru *LRU[T]) Set(key string, value T) bool {
	lru.Lock()
	defer lru.Unlock()

	if itm, ok := lru.items[key]; ok {
		itm.value = value
		itm.element.Value = key
		lru.keyList.MoveToFront(itm.element)
		return true
	}

	newItem := &item[T]{key: key, value: value}
	newItem.element = lru.keyList.PushFront(newItem)
	lru.items[key] = newItem
	lru.currentSize += 1

	for lru.currentSize > lru.maxSize {
		lru.removeOldest()
	}
	return true
}

func (lru *LRU[T]) Len() int {
	lru.Lock()
	defer lru.Unlock()
	return lru.keyList.Len()
}

func (lru *LRU[T]) removeOldest() {
	if lru.keyList.Len() == 0 {
		return
	}
	oldest := lru.keyList.Back()
	if oldest != nil {
		itm := oldest.Value.(*item[T])
		if itm, found := lru.items[itm.key]; found {
			delete(lru.items, itm.key)
			lru.currentSize -= 1
		}
		lru.keyList.Remove(oldest)
	}
}
