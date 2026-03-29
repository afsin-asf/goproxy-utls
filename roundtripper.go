// roundtripper.go
package goproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"sync"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Wrapper for utls.UConn that ensures proper HTTP/2 support in http.Transport
// The issue is that http.Transport checks for HTTP/2 support in specific ways
// that don't work with utls connections by default. This wrapper ensures
// that the connection reports HTTP/2 protocol negotiation correctly.
type http2CompatibleConn struct {
	net.Conn
	uConn *utls.UConn
}

// ConnectionState returns the TLS connection state, needed for HTTP/2 detection in http.Transport
func (c *http2CompatibleConn) ConnectionState() tls.ConnectionState {
	// Convert utls ConnectionState to standard crypto/tls ConnectionState
	uState := c.uConn.ConnectionState()
	
	// Map the protocol negotiation information correctly
	return tls.ConnectionState{
		Version:                     uState.Version,
		HandshakeComplete:           uState.HandshakeComplete,
		DidResume:                   uState.DidResume,
		CipherSuite:                 uState.CipherSuite,
		NegotiatedProtocol:          uState.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  uState.NegotiatedProtocolIsMutual,
		ServerName:                  uState.ServerName,
		PeerCertificates:            uState.PeerCertificates,
		VerifiedChains:              uState.VerifiedChains,
		OCSPResponse:                uState.OCSPResponse,
		TLSUnique:                   uState.TLSUnique,
	}
}

// Implement net.Conn interface delegation
func (c *http2CompatibleConn) Read(b []byte) (int, error) {
	return c.uConn.Read(b)
}

func (c *http2CompatibleConn) Write(b []byte) (int, error) {
	return c.uConn.Write(b)
}

func (c *http2CompatibleConn) Close() error {
	return c.uConn.Close()
}

func newUTLSTransport(spec *utls.ClientHelloSpec, disableCompression bool, nextProtos []string) http.RoundTripper {
    dialTLSContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
        rawConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
        if err != nil {
            return nil, err
        }

        host, _, _ := net.SplitHostPort(addr)

        // Context'ten spec'i oku
        contextSpec, ok := ctx.Value("clientHelloSpec").(*utls.ClientHelloSpec)
        if !ok {
            contextSpec = spec  // Fallback to original spec
        }

        var protos []string
        if contextSpec != nil {
            protos = extractALPNFromSpec(contextSpec)
            if len(protos) == 0 {
                protos = []string{"h2", "http/1.1"}
            }
        } else {
            protos = []string{"h2", "http/1.1"}
            if len(nextProtos) > 0 {
                protos = nextProtos
            }
        }

        tlsConfig := &utls.Config{
            ServerName:         host,
            InsecureSkipVerify: true,
            NextProtos:         protos,
        }

        var helloID utls.ClientHelloID
        if contextSpec == nil {
            helloID = utls.HelloChrome_Auto
        } else {
            helloID = utls.HelloCustom
        }

        uConn := utls.UClient(rawConn, tlsConfig, helloID)

        if contextSpec != nil {
            if err := uConn.ApplyPreset(contextSpec); err != nil {
                rawConn.Close()
                rawConn2, err2 := (&net.Dialer{}).DialContext(ctx, network, addr)
                if err2 != nil {
                    return nil, err2
                }
                uConn = utls.UClient(rawConn2, tlsConfig, utls.HelloChrome_Auto)
            }
        }

        if err := uConn.HandshakeContext(ctx); err != nil {
            uConn.Close()
            return nil, err
        }

        return uConn, nil
    }

    // HTTP/1.1 transport
    h1Transport := &http.Transport{
        DialContext:         (&net.Dialer{}).DialContext,
        DialTLSContext:      dialTLSContext,
        MaxIdleConnsPerHost: 100,
        DisableCompression:  disableCompression,
    }

    // HTTP/2 transport — ayrı, kendi dial fonksiyonuyla
    h2Transport := &http2.Transport{
        DisableCompression: disableCompression,
        DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
            return dialTLSContext(ctx, network, addr)
        },
    }

    // Protokol seçimini otomatik yapan wrapper
    return &autoH2RoundTripper{
        h1:             h1Transport,
        h2:             h2Transport,
        spec:           spec,
        dialTLSContext: dialTLSContext,
    }
}

type autoH2RoundTripper struct {
    h1             *http.Transport
    h2             *http2.Transport
    spec           *utls.ClientHelloSpec // Store for access in RoundTrip
    dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)
    
    mu          sync.RWMutex
    knownH2     map[string]bool // host -> supports h2
}

// Globally apply HTTP/2 config to proxy.Tr if it has h2 in NextProtos
// This is done in a thread-safe way on first use
var (
	http2ConfiguredTransports sync.Map // Track which transports have been configured with http2
)

func markHTTP2Configured(tr *http.Transport) {
	http2ConfiguredTransports.Store(tr, true)
}

func isHTTP2Configured(tr *http.Transport) bool {
	_, ok := http2ConfiguredTransports.Load(tr)
	return ok
}

func (rt *autoH2RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
    if req.URL.Scheme != "https" {
        return rt.h1.RoundTrip(req)
    }

    addr := req.URL.Host
    if _, _, err := net.SplitHostPort(addr); err != nil {
        addr += ":443"
    }

    // Check if we already know this host speaks h2
    rt.mu.RLock()
    isH2, known := rt.knownH2[addr]
    rt.mu.RUnlock()

    if known && isH2 {
        return rt.h2.RoundTrip(req)
    }
    if known && !isH2 {
        return rt.h1.RoundTrip(req)
    }

    // First contact: probe by dialing - ClientHelloSpec'i context'e koy
    ctx := context.WithValue(req.Context(), "clientHelloSpec", rt.spec)
    conn, err := rt.dialTLSContext(ctx, "tcp", addr)
    if err != nil {
        return nil, err
    }

    // Check negotiated protocol
    uConn, ok := conn.(*utls.UConn)
    if !ok {
        conn.Close()
        return nil, fmt.Errorf("unexpected connection type")
    }

    negotiated := uConn.ConnectionState().NegotiatedProtocol

    rt.mu.Lock()
    if rt.knownH2 == nil {
        rt.knownH2 = make(map[string]bool)
    }
    rt.knownH2[addr] = (negotiated == "h2")
    rt.mu.Unlock()

    if negotiated == "h2" {
        // Give this connection to h2 transport
        conn.Close() // h2.Transport will dial its own connection
        return rt.h2.RoundTrip(req)
    }

    // HTTP/1.1 — feed this connection back
    conn.Close() // h1 transport will dial its own
    return rt.h1.RoundTrip(req)
}

func (proxy *ProxyHttpServer) getOrCreateTransport(
	spec *utls.ClientHelloSpec,
) http.RoundTripper {
	// Include both spec hash and compression setting in cache key
	specKey := fingerprintSpecHash(spec)
	compressionKey := "0"
	if proxy.Tr.DisableCompression {
		compressionKey = "1"
	}
	key := specKey + "-" + compressionKey

	// Check cache
	if tr, ok := proxy.transportCache[key]; ok {
		return tr
	}

	// Special case: if no spec and proxy.Tr has HTTP/2 setup, use it as-is
	if spec == nil && proxy.Tr.TLSClientConfig != nil {
		// Check if proxy.Tr was explicitly set up for HTTP/2
		hasH2 := false
		for _, proto := range proxy.Tr.TLSClientConfig.NextProtos {
			if proto == "h2" {
				hasH2 = true
				break
			}
		}
		if hasH2 && proxy.Tr.DialTLSContext == nil {
			// Apply HTTP/2 support to proxy.Tr if not already configured
			if !isHTTP2Configured(proxy.Tr) {
				http2.ConfigureTransport(proxy.Tr)
				markHTTP2Configured(proxy.Tr)
			}
			// Return it directly without caching (it's user-managed)
			return proxy.Tr
		}
	}

	// Create transport with the proxy's DisableCompression setting
	tr := newUTLSTransport(spec, proxy.Tr.DisableCompression, nil)

	// Store in cache
	proxy.transportCache[key] = tr

	return tr
}

func (proxy *ProxyHttpServer) getDefaultUTLSTransport() http.RoundTripper {
	// Use nil spec to get Chrome default fingerprint
	return proxy.getOrCreateTransport(nil)
}

func fingerprintSpecHash(spec *utls.ClientHelloSpec) string {
	if spec == nil {
		return "default-chrome"
	}
	// Simple hash based on cipher suites and extensions
	h := sha256.New()
	for _, suite := range spec.CipherSuites {
		binary.Write(h, binary.BigEndian, suite)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// extractALPNFromSpec extracts ALPN (Application-Layer Protocol Negotiation) protocols
// from a ClientHelloSpec's extensions
func extractALPNFromSpec(spec *utls.ClientHelloSpec) []string {
	if spec == nil || spec.Extensions == nil {
		return nil
	}

	// ExtensionApplicationLayerProtocolNegotiation is ID 16
	for _, ext := range spec.Extensions {
		if ext.Len() == 0 {
			continue
		}
		// Check if this is the ALPN extension (ID 16)
		// We need to access the extension data and parse it
		// For now, return h2 if any extension exists, as a safe default
		// TODO: Parse ALPN data properly to extract actual protocol names
	}
	return nil
}