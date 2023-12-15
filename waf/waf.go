package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"rule-cache-waf/waf/cache"
	"sync"
)

type RuleCacheWAF struct {
	Cert         tls.Certificate
	OriginURL    *url.URL
	Proxy        *httputil.ReverseProxy
	ProxyHandler func(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request)
	Rules        []Rule
	RulesMap     map[int]Rule
	Cache        *cache.LRU[int] // cache last used rule for IP
	CacheHits    int             // records the number of cache hits

	// TLS Fingerprinting
	clientHelloInfoStore       map[string]tls.ClientHelloInfo
	clientHelloInfoStoreLock   sync.RWMutex
	fingerprintsToCheckAgainst []PartialClientHelloFingerprint

	// IP Fingerprinting
	blockedSubnets []*net.IPNet

	// Header Fingerprinting
	validHeaders []string
}

type Rule struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

func NewRuleCacheWAF(config *WAFConfig) (*RuleCacheWAF, error) {
	originURL, err := url.Parse(config.OriginURL)
	if err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(config.CertFileLocation, config.KeyFileLocation)
	if err != nil {
		log.Fatalln(err)
	}

	var blockedSubnets []*net.IPNet
	for _, subnetStr := range config.BlockedSubnets {
		_, subnet, err := net.ParseCIDR(subnetStr)
		if err != nil {
			return nil, err
		}
		blockedSubnets = append(blockedSubnets, subnet)
	}

	return &RuleCacheWAF{
		OriginURL:                originURL,
		Rules:                    config.Rules,
		blockedSubnets:           blockedSubnets,
		validHeaders:             config.ValidHeaders,
		Cert:                     cert,
		clientHelloInfoStore:     make(map[string]tls.ClientHelloInfo),
		clientHelloInfoStoreLock: sync.RWMutex{},
		Cache:                    cache.NewLru[int](10),
		CacheHits:                0,
		fingerprintsToCheckAgainst: []PartialClientHelloFingerprint{
			SafariFingerprint,
			ChromeFingerprint,
		},
	}, nil
}

func (w *RuleCacheWAF) tlsFingerprintClient(info tls.ClientHelloInfo, r *http.Request) bool {
	clientFingerprint := PartialClientHelloFingerprint{
		Version:           r.TLS.Version,
		CipherSuites:      info.CipherSuites,
		SupportedProtos:   info.SupportedProtos,
		SupportedPoints:   info.SupportedPoints,
		SupportedVersions: info.SupportedVersions[1:], // ignore GREASE
		SupportedCurves:   info.SupportedCurves[1:],
	}

	matched := false
	for _, validFingerprint := range w.fingerprintsToCheckAgainst {
		if clientFingerprint.Version == validFingerprint.Version &&
			compareFieldLenient(clientFingerprint.CipherSuites, validFingerprint.CipherSuites) &&
			compareFieldStrict(clientFingerprint.SupportedProtos, validFingerprint.SupportedProtos) &&
			compareFieldStrict(clientFingerprint.SupportedPoints, validFingerprint.SupportedPoints) &&
			compareFieldStrict(clientFingerprint.SupportedVersions, validFingerprint.SupportedVersions) &&
			compareFieldStrict(clientFingerprint.SupportedCurves, validFingerprint.SupportedCurves) {
			matched = true
			break
		}
	}

	return !matched
}

func (w *RuleCacheWAF) IsIPBlocked(r *http.Request) bool {
	ip := net.ParseIP(r.RemoteAddr)
	if ip == nil {
		return false
	}

	for _, subnet := range w.blockedSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}

	return false
}

func (w *RuleCacheWAF) PrettyJSONFingerprinting(r *http.Request) bool {
	var bodyBytes []byte
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return true
	}

	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	var jsonData interface{}
	if err := json.Unmarshal(bodyBytes, &jsonData); err != nil {
		return true
	}

	prettyJSON, err := json.MarshalIndent(jsonData, "", "  ")
	if err != nil {
		return true
	}

	return string(prettyJSON) != string(bodyBytes)
}

func (w *RuleCacheWAF) HeaderFingerprinting(r *http.Request) bool {
	if !headersPresent(r.Header, w.validHeaders) || !headersCanonical(r.Header) {
		return true
	}

	return false
}

func headersPresent(headers http.Header, expectedHeaders []string) bool {
	for _, header := range expectedHeaders {
		if _, ok := headers[header]; !ok {
			return false
		}
	}
	return true
}

func headersCanonical(headers http.Header) bool {
	for name := range headers {
		if http.CanonicalHeaderKey(name) != name {
			return false
		}
	}
	return true
}

func applyRule(waf *RuleCacheWAF, ruleID int, r *http.Request) bool {
	var result bool
	clientIP := r.RemoteAddr

	switch ruleID {
	case 0:
		result = ruleCacheWAF.IsIPBlocked(r)
	case 1:
		result = waf.HeaderFingerprinting(r)
	case 2:
		result = waf.PrettyJSONFingerprinting(r)
	case 3:
		ruleCacheWAF.clientHelloInfoStoreLock.Lock()
		clientHelloInfo := ruleCacheWAF.clientHelloInfoStore[r.RemoteAddr]
		ruleCacheWAF.clientHelloInfoStoreLock.Unlock()
		result = waf.tlsFingerprintClient(clientHelloInfo, r)
	}

	if result {
		ruleCacheWAF.Cache.Set(clientIP, ruleID)
	}

	return result
}
