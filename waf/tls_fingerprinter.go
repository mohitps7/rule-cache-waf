package main

import (
	"crypto/tls"
)

type PartialClientHelloFingerprint struct {
	Version           uint16
	CipherSuites      []uint16
	SupportedProtos   []string
	SupportedPoints   []uint8
	SupportedVersions []uint16
	SupportedCurves   []tls.CurveID
}

var SafariFingerprint = PartialClientHelloFingerprint{
	Version: uint16(tls.VersionTLS13),
	CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	},
	SupportedProtos:   []string{"h2", "http/1.1"},
	SupportedPoints:   []uint8{0},
	SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12, tls.VersionTLS11, tls.VersionTLS10},
	SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
}

var ChromeFingerprint = PartialClientHelloFingerprint{
	Version: tls.VersionTLS13,
	CipherSuites: []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	},
	SupportedProtos:   []string{"h2", "http/1.1"},
	SupportedPoints:   []uint8{0},
	SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
	SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
}

func compareFieldStrict[T string | uint8 | uint16 | tls.CurveID](a, b []T) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func compareFieldLenient[T string | uint8 | uint16 | tls.CurveID](a, b []T) bool {
	for _, u := range b {
		found := false
		for _, v := range a {
			if v == u {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
