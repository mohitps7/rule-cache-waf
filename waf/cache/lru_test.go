package cache

import (
	"fmt"
	"testing"
)

func TestFIFO(t *testing.T) {
	capacity := 64

	cache := NewLru[string](capacity)

	checkCapacity(t, cache, capacity)

	for i := 0; i < 4; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		rule := fmt.Sprintf("Rule%d", i)

		ok := cache.Set(ip, rule)
		if !ok {
			t.Errorf("Failed to add binding for IP: %s", ip)
			t.FailNow()
		}

		res, _ := cache.Get(ip)
		if res != rule {
			t.Errorf("Wrong rule %s for IP: %s", res, ip)
			t.FailNow()
		}
	}
}

func checkCapacity[T any](t *testing.T, cache *LRU[T], capacity int) {
	maxCapacity := cache.MaxStorage()
	if maxCapacity != capacity {
		t.Errorf("Expected cache to have %d MaxStorage, but it had %d", capacity, maxCapacity)
	}
}
