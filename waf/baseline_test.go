package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestBaselinePerformanceWithoutCache(t *testing.T) {
	config, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	ruleCacheWAF, err = NewRuleCacheWAF(config)
	if err != nil {
		log.Fatalf("Failed to initialize RuleCacheWAF: %v", err)
	}

	startTime := time.Now()

	for i := 0; i < 5000; i++ {
		blockedReq := httptest.NewRequest("GET", "https://localhost:9001", nil)
		blockedReq.RemoteAddr = "192.168.1.1"
		isMalicious := false

		for _, rule := range ruleCacheWAF.Rules {
			t.Logf("Applying Rule: %s %v\n", rule.Name, rule.ID)
			isMalicious = applyRule(ruleCacheWAF, rule.ID, blockedReq)
			if isMalicious {
				t.Logf("Client Blocked Using Cache - IP: %v", blockedReq.RemoteAddr)
				break
			}
		}
	}

	endTime := time.Now()
	elapsedTime := endTime.Sub(startTime)

	t.Logf("Baseline Performance Test Without Cache: Elapsed Time - %v", elapsedTime)
}

func TestBaselinePerformanceWithCache(t *testing.T) {
	config, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	ruleCacheWAF, err = NewRuleCacheWAF(config)
	if err != nil {
		log.Fatalf("Failed to initialize RuleCacheWAF: %v", err)
	}

	startTime := time.Now()

	for i := 0; i < 5000; i++ {
		blockedReq := httptest.NewRequest("GET", "https://localhost:9001", nil)
		blockedReq.RemoteAddr = "192.168.1.1" // malicious + should be blocked
		clientIP := blockedReq.RemoteAddr
		isMalicious := false
		var ruleID int
		var found bool

		if ruleID, found = ruleCacheWAF.Cache.Get(clientIP); found {
			t.Logf("Applying Cached Rule: %v\n", ruleID)
			isMalicious = applyRule(ruleCacheWAF, ruleID, blockedReq)
			if isMalicious {
				t.Logf("Client Blocked Using Cache - IP: %v", blockedReq.RemoteAddr)
				break
			}
		}
		for _, rule := range ruleCacheWAF.Rules {
			t.Logf("Applying Rule: %s %v\n", rule.Name, rule.ID)
			isMalicious = applyRule(ruleCacheWAF, rule.ID, blockedReq)
			if isMalicious {
				t.Logf("Client Blocked Using Cache - IP: %v", blockedReq.RemoteAddr)
				break
			}
		}
	}

	endTime := time.Now()
	elapsedTime := endTime.Sub(startTime)

	t.Logf("Baseline Performance Test With Cache: Elapsed Time - %v", elapsedTime)
}

func BenchmarkCacheHitRate(b *testing.B) {
	config, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	ruleCacheWAF, err = NewRuleCacheWAF(config)
	if err != nil {
		log.Fatalf("Failed to initialize RuleCacheWAF: %v", err)
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applyRule(ruleCacheWAF, 0, r)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	defer testServer.Close()

	for i := 0; i < 100; i++ {
		makeRequest(testServer.URL, ruleCacheWAF)
	}

	ruleCacheWAF.CacheHits = 0

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		makeRequest(testServer.URL, ruleCacheWAF)
	}
	b.StopTimer()

	cacheHitRate := float64(ruleCacheWAF.CacheHits) / float64(b.N) * 100
	fmt.Printf("Cache Hit Rate: %.2f%%\n", cacheHitRate)
}

func BenchmarkConcurrencyTest(b *testing.B) {
	config, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	ruleCacheWAF, err = NewRuleCacheWAF(config)
	if err != nil {
		log.Fatalf("Failed to initialize RuleCacheWAF: %v", err)
	}

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applyRule(ruleCacheWAF, 0, r)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	defer testServer.Close()

	numConcurrentRequests := 1000

	var wg sync.WaitGroup
	wg.Add(numConcurrentRequests)

	startTime := time.Now()

	b.ResetTimer()
	for i := 0; i < numConcurrentRequests; i++ {
		go func() {
			defer wg.Done()

			makeRequest(testServer.URL, ruleCacheWAF)
		}()
	}

	wg.Wait()
	b.StopTimer()

	endTime := time.Now()

	elapsedTime := endTime.Sub(startTime)
	b.Logf("Baseline Performance Test With %d Concurrent Requests: Elapsed Time - %v", numConcurrentRequests, elapsedTime)
}

func makeRequest(url string, waf *RuleCacheWAF) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error making request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}

	_ = processResponse(body, waf)
}

func processResponse(body []byte, waf *RuleCacheWAF) bool {
	if string(body) == "OK" {
		waf.CacheHits++
		return true
	}
	return false
}
