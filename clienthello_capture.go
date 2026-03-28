package goproxy

import (
	"net"

	tls "github.com/refraction-networking/utls"
)

// capturingConn wraps a net.Conn and captures the first TLS record (ClientHello) seen when reading
type capturingConn struct {
	net.Conn
	captured      bool
	capturedBytes []byte
	onCapture     func([]byte)
}

// Read intercepts the connection read to capture the ClientHello
// Important: We capture the bytes for fingerprinting but still return them to the caller
func (c *capturingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	
	if !c.captured && n > 0 {
		// Capture the data seen on first read if it's a TLS handshake record (type 0x16)
		if b[0] == 0x16 { // TLS handshake record type
			// Store a copy of the captured bytes for fingerprinting
			c.capturedBytes = make([]byte, n)
			copy(c.capturedBytes, b[:n])
			c.captured = true
			if c.onCapture != nil {
				c.onCapture(c.capturedBytes)
			}
		}
	}
	
	// Always return the full data to the caller - we only captured for fingerprinting
	return n, err
}

// wrapConnToCapture creates a connection wrapper that captures the ClientHello bytes
// The wrapper transparently forwards all operations while capturing the first TLS record
func wrapConnToCapture(conn net.Conn, onCapture func([]byte)) net.Conn {
	return &capturingConn{
		Conn:      conn,
		onCapture: onCapture,
	}
}

// fingerprintClientHello extracts and fingerprints a ClientHello from raw bytes
// rawBytes should include the full TLS record (with type/version/length header)
// Returns nil if fingerprinting fails (caller should handle gracefully)
func fingerprintClientHello(rawBytes []byte) *tls.ClientHelloSpec {
	fingerprinter := &tls.Fingerprinter{}
	spec, err := fingerprinter.FingerprintClientHello(rawBytes)
	if err != nil {
		// Failed to fingerprint - will fall back to default
		return nil
	}
	return spec
}

// createClientHelloFrom creates a new ClientHello that mimics the original spec
// Returns the UConn ready to use the spec
func createClientHelloFrom(targetConn net.Conn, spec *tls.ClientHelloSpec, tlsConfig *tls.Config) (*tls.UConn, error) {
	// Start with the provided tlsConfig (which has ServerName set)
	// Use HelloCustom to get an empty config that we can populate with the spec
	uConn := tls.UClient(targetConn, tlsConfig, tls.HelloCustom)
	
	// Apply the captured spec to match the original client's fingerprint
	if err := uConn.ApplyPreset(spec); err != nil {
		return nil, err
	}
	
	return uConn, nil
}
