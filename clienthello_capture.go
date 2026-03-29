package goproxy

import (
	"io"
	"net"
	"sync"

	tls "github.com/refraction-networking/utls"
)

const (
	_tlsRecordTypeHandshake uint8 = 0x16
	_tlsHandshakeClientHello uint8 = 0x01
)

// capturingBufferedReader wraps an io.Reader (like a bufio.Reader) and forwards
// all data to a clientHelloCaptureConn for capture, while still serving the data.
type capturingBufferedReader struct {
	source      io.Reader
	captureConn *clientHelloCaptureConn
}

func (c *capturingBufferedReader) Read(b []byte) (int, error) {
	n, err := c.source.Read(b)
	if n > 0 {
		// Forward ALL data through the capture wrapper
		captured := make([]byte, n)
		copy(captured, b[:n])
		// Simulate a Read through the capture wrapper
		if !c.captureConn.captured {
			c.captureConn.mu.Lock()
			if c.captureConn.capturing {
				c.captureConn.buf = append(c.captureConn.buf, captured...)
				c.captureConn.tryExtractClientHello()
			}
			c.captureConn.mu.Unlock()
		}
	}
	return n, err
}

// clientHelloCaptureConn wraps a net.Conn and captures the raw ClientHello
// message during the TLS handshake. It does NOT consume bytes — it copies
// them as they pass through Read().
type clientHelloCaptureConn struct {
	net.Conn

	mu             sync.Mutex
	capturing      bool
	captured       bool
	buf            []byte
	clientHello    []byte
}

func newClientHelloCaptureConn(c net.Conn) *clientHelloCaptureConn {
	return &clientHelloCaptureConn{
		Conn:      c,
		capturing: true,
	}
}

func (c *clientHelloCaptureConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		if c.capturing && !c.captured {
			c.buf = append(c.buf, b[:n]...)
			c.tryExtractClientHello()
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *clientHelloCaptureConn) tryExtractClientHello() {
	buf := c.buf

	// Need at least 5 bytes for TLS record header
	if len(buf) < 5 {
		return
	}

	// Check: TLS record type = Handshake (0x16)
	if buf[0] != _tlsRecordTypeHandshake {
		c.capturing = false
		return
	}

	// TLS record length (bytes 3-4, big endian)
	recordLen := int(buf[3])<<8 | int(buf[4])
	totalLen := 5 + recordLen

	// Wait until we have the full record
	if len(buf) < totalLen {
		return
	}

	// Check: Handshake type = ClientHello (0x01) at byte 5
	if len(buf) > 5 && buf[5] != _tlsHandshakeClientHello {
		c.capturing = false
		return
	}

	// We have the complete ClientHello record
	c.clientHello = make([]byte, totalLen)
	copy(c.clientHello, buf[:totalLen])
	c.captured = true
	c.capturing = false
}

// ClientHelloBytes returns the captured raw ClientHello or nil if not captured.
func (c *clientHelloCaptureConn) ClientHelloBytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.clientHello
}

// fingerprintClientHello extracts and fingerprints a ClientHello from raw bytes
// rawBytes should include the full TLS record (with type/version/length header)
// Returns nil if fingerprinting fails (caller should handle gracefully)
func fingerprintClientHello(rawBytes []byte) *tls.ClientHelloSpec {
	// Try using FromRaw which is more flexible with unknown extensions
	spec := &tls.ClientHelloSpec{}
	err := spec.FromRaw(rawBytes)
	if err == nil {
		return spec
	}

	// If FromRaw fails, try Fingerprinter (which has stricter parsing)
	fingerprinter := &tls.Fingerprinter{}
	spec2, err := fingerprinter.FingerprintClientHello(rawBytes)
	if err != nil {
		// Failed to fingerprint - will fall back to default
		return nil
	}
	return spec2
}

// stripExtension49 placeholder for potential future use
func stripExtension49(rawBytes []byte) []byte {
	// Extension 49 (post_handshake_auth) is not yet supported by utls
	// but ClientHelloSpec.FromRaw should handle it gracefully
	return nil
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
