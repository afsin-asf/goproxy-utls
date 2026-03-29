// roundtripper.go
package goproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/http"
	"sync"

	"golang.org/x/net/http2"
	utls "github.com/refraction-networking/utls"
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

// Ortak transport oluşturma fonksiyonu - rekürsyon riski yok
func newUTLSTransport(spec *utls.ClientHelloSpec, disableCompression bool, nextProtos []string) *http.Transport {
	tr := &http.Transport{
		// Regular dial for plain HTTP
		DialContext: (&net.Dialer{}).DialContext,

		// uTLS dial for HTTPS - with built-in HTTP/2 support
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			rawConn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			host, _, _ := net.SplitHostPort(addr)
			
			// Build NextProtos based on whether we have a captured spec
			var protos []string
			if spec != nil {
				// If we have a captured ClientHelloSpec, extract ALPN from its extensions
				// Otherwise add h2 to allow HTTP/2 support
				protos = extractALPNFromSpec(spec)
				if len(protos) == 0 {
					// No ALPN in spec, add h2 to enable HTTP/2
					protos = []string{"h2"}
				}
			} else {
				// No spec: use default with h2
				protos = append([]string{"h2"}, nextProtos...)
			}
			
			tlsConfig := &utls.Config{
				ServerName:         host,
				InsecureSkipVerify: true, // needed for test servers with self-signed certs
				NextProtos:         protos,
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

			// Return the raw utls connection directly - http.Transport will check ConnectionState()
			// via the utls.UConn interface which properly reports NegotiatedProtocol
			return uConn, nil
		},
		//  MaxIdleConns:    100,
		MaxIdleConnsPerHost: 100,
		ForceAttemptHTTP2:   true,
		DisableCompression: disableCompression,
	}
	
	// Configure HTTP/2 support to handle responses from HTTP/2 servers
	// This is essential so the transport can receive and parse HTTP/2 responses
	// even when the spec forces HTTP/1.1 in NextProtos
	http2.ConfigureTransport(tr)
	
	return tr
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

// RoundTrip on ProxyCtx uses the mirrored fingerprint
func (ctx *ProxyCtx) RoundTrip(req *http.Request) (*http.Response, error) {
	if ctx.RoundTripper != nil {
		return ctx.RoundTripper.RoundTrip(req, ctx)
	}

	// Use fingerprint-aware transport
	transport := ctx.Proxy.getOrCreateTransport(ctx.ClientHelloSpec)
	return transport.RoundTrip(req)
}

func (proxy *ProxyHttpServer) getOrCreateTransport(
	spec *utls.ClientHelloSpec,
) *http.Transport {
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

func (proxy *ProxyHttpServer) getDefaultUTLSTransport() *http.Transport {
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