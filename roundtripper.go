// roundtripper.go
package goproxy

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/http"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// RoundTrip on ProxyCtx uses the mirrored fingerprint
func (ctx *ProxyCtx) RoundTrip(req *http.Request) (*http.Response, error) {
	if ctx.RoundTripper != nil {
		return ctx.RoundTripper.RoundTrip(req, ctx)
	}

	// Use fingerprint-aware transport
	transport := ctx.Proxy.getOrCreateTransport(ctx.ClientHelloSpec)
	return transport.RoundTrip(req)
}

// Transport cache - one transport per unique fingerprint
type fingerprintTransportCache struct {
	mu    sync.RWMutex
	cache map[string]*http.Transport // key = fingerprint hash
}

var transportCache = &fingerprintTransportCache{
	cache: make(map[string]*http.Transport),
}

func (proxy *ProxyHttpServer) getOrCreateTransport(spec *utls.ClientHelloSpec) *http.Transport {
	// No fingerprint captured — use default Chrome
	if spec == nil {
		return proxy.getDefaultUTLSTransport()
	}

	// Create new transport with this fingerprint
	var nextProtos []string
	if proxy.Tr.TLSClientConfig != nil {
		nextProtos = proxy.Tr.TLSClientConfig.NextProtos
	}
	
	// Use cache key that includes both spec and NextProtos
	key := fingerprintSpecHash(spec, proxy.Tr.DisableCompression, nextProtos)

	transportCache.mu.RLock()
	if tr, ok := transportCache.cache[key]; ok {
		transportCache.mu.RUnlock()
		return tr
	}
	transportCache.mu.RUnlock()

	// Create new transport with this fingerprint
	tr := newUTLSTransport(spec, proxy.Tr.DisableCompression, nextProtos)

	transportCache.mu.Lock()
	transportCache.cache[key] = tr
	transportCache.mu.Unlock()

	return tr
}

// Ortak transport oluşturma fonksiyonu - rekürsyon riski yok
func newUTLSTransport(spec *utls.ClientHelloSpec, disableCompression bool, nextProtos []string) *http.Transport {
	return &http.Transport{
		// Regular dial for plain HTTP
		DialContext: (&net.Dialer{}).DialContext,

		// uTLS dial for HTTPS
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rawConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			host, _, _ := net.SplitHostPort(addr)
			tlsConfig := &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: true, // needed for test servers with self-signed certs
				NextProtos:         append([]string{"h2"}, nextProtos...), // Always try HTTP/2 first
			}

			var helloID utls.ClientHelloID
			if spec == nil {
				helloID = utls.HelloChrome_Auto
			} else {
				helloID = utls.HelloCustom
			}

			uConn := utls.UClient(rawConn, tlsConfig, helloID)

			if spec != nil {
				if err := uConn.ApplyPreset(spec); err != nil {
					rawConn.Close()
					rawConn2, err := (&net.Dialer{}).DialContext(ctx, network, addr)
					if err != nil {
						return nil, err
					}
					uConn = utls.UClient(rawConn2, tlsConfig, utls.HelloChrome_Auto)
				}
			}

			if err := uConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				return nil, err
			}

			return uConn, nil
		},
		ForceAttemptHTTP2:   true,
		DisableCompression: disableCompression,
	}
}
func (proxy *ProxyHttpServer) getDefaultUTLSTransport() *http.Transport {
	// Default: Chrome fingerprint with DisableCompression setting and proxy TLS config
	var nextProtos []string
	if proxy.Tr.TLSClientConfig != nil {
		nextProtos = proxy.Tr.TLSClientConfig.NextProtos
	}
	
	// Create a key that includes DisableCompression and NextProtos
	key := fingerprintSpecHash(nil, proxy.Tr.DisableCompression, nextProtos)

	transportCache.mu.RLock()
	if tr, ok := transportCache.cache[key]; ok {
		transportCache.mu.RUnlock()
		return tr
	}
	transportCache.mu.RUnlock()

	tr := newUTLSTransport(nil, proxy.Tr.DisableCompression, nextProtos)

	transportCache.mu.Lock()
	transportCache.cache[key] = tr
	transportCache.mu.Unlock()

	return tr
}


func fingerprintSpecHash(spec *utls.ClientHelloSpec, disableCompression bool, nextProtos []string) string {
	h := sha256.New()
	
	if spec == nil {
		h.Write([]byte("default-chrome"))
	} else {
		// Hash based on cipher suites
		for _, suite := range spec.CipherSuites {
			binary.Write(h, binary.BigEndian, suite)
		}
	}
	
	// Include compression setting in the hash
	if disableCompression {
		h.Write([]byte("-no-compression"))
	}
	
	// Include NextProtos in the hash to distinguish different HTTP/2 configs
	for _, proto := range nextProtos {
		h.Write([]byte("-" + proto))
	}
	
	return hex.EncodeToString(h.Sum(nil))[:16]
}