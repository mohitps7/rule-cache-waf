package main

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/http/httputil"
	"time"
)

var ruleCacheWAF *RuleCacheWAF

func main() {
	var err error

	config, err := LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	ruleCacheWAF, err = NewRuleCacheWAF(config)
	if err != nil {
		log.Fatalf("Failed to initialize RuleCacheWAF: %v", err)
	}

	ruleCacheWAF.ProxyHandler = func(p *httputil.ReverseProxy) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.ProtoMajor != 2 {
				p.ServeHTTP(w, r)
				return
			}
			r.Host = ruleCacheWAF.OriginURL.Host

			clientIP := r.RemoteAddr
			isMalicious := false
			var ruleID int
			var found bool

			if ruleID, found = ruleCacheWAF.Cache.Get(clientIP); found {
				log.Printf("Applying Cached Rule: %v\n", ruleID)
				isMalicious = applyRule(ruleCacheWAF, ruleID, r)
				if isMalicious {
					log.Printf("Client Blocked Using Cache - IP: %v", r.RemoteAddr)
					w.WriteHeader(403)
					w.Write([]byte("Blocked - Client does not meet specified requirements"))
					return
				}
			}

			for _, rule := range ruleCacheWAF.Rules {
				log.Printf("Applying Rule: %s %v\n", rule.Name, rule.ID)
				isMalicious = applyRule(ruleCacheWAF, rule.ID, r)
				if isMalicious {
					break
				}
			}

			if isMalicious {
				log.Printf("Client Blocked - IP: %v", r.RemoteAddr)
				w.WriteHeader(403)
				w.Write([]byte("Blocked - Client does not meet specified requirements"))
				return
			}

			p.ServeHTTP(w, r)
			return
		}
	}

	ruleCacheWAF.Proxy = httputil.NewSingleHostReverseProxy(ruleCacheWAF.OriginURL)
	ruleCacheWAF.Proxy.Transport = &http.Transport{
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		GetCertificate:     getClientInfo,
	}

	ln, err := tls.Listen("tcp", ":9001", tlsConfig)
	http.HandleFunc("/", ruleCacheWAF.ProxyHandler(ruleCacheWAF.Proxy))

	log.Println("Serving on :9001")
	err = http.Serve(ln, nil)
	if err != nil {
		panic(err)
	}
}

func getClientInfo(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
	ruleCacheWAF.clientHelloInfoStoreLock.Lock()
	defer ruleCacheWAF.clientHelloInfoStoreLock.Unlock()

	remoteAddrString := info.Conn.RemoteAddr().String()
	if _, ok := ruleCacheWAF.clientHelloInfoStore[remoteAddrString]; !ok {
		ruleCacheWAF.clientHelloInfoStore[remoteAddrString] = *info
	}

	return &ruleCacheWAF.Cert, nil
}
