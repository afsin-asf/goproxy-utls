package goproxy

import (
	"bufio"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	tls "github.com/refraction-networking/utls"
)

func headerContains(header http.Header, name string, value string) bool {
	for _, v := range header[name] {
		for _, s := range strings.Split(v, ",") {
			if strings.EqualFold(value, strings.TrimSpace(s)) {
				return true
			}
		}
	}
	return false
}

func isWebSocketHandshake(header http.Header) bool {
	return headerContains(header, "Connection", "Upgrade") &&
		headerContains(header, "Upgrade", "websocket")
}

// computeSecWebSocketAccept computes the Sec-WebSocket-Accept header value
// from the Sec-WebSocket-Key header value as per RFC 6455 Section 4.2.2
func computeSecWebSocketAccept(key string) string {
	const magicString = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	h.Write([]byte(key + magicString))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (proxy *ProxyHttpServer) hijackConnection(ctx *ProxyCtx, w http.ResponseWriter) (net.Conn, error) {
	// Connect to Client
	hj, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		ctx.Warnf("Hijack error: %v", err)
		return nil, err
	}
	return clientConn, nil
}

func (proxy *ProxyHttpServer) proxyWebsocket(ctx *ProxyCtx, remoteConn io.ReadWriter, proxyClient io.ReadWriter) {
	// 2 is the number of goroutines, this code is implemented according to
	// https://stackoverflow.com/questions/52031332/wait-for-one-goroutine-to-finish
	waitChan := make(chan struct{}, 2)
	go func() {
		_ = copyOrWarn(ctx, remoteConn, proxyClient)
		waitChan <- struct{}{}
	}()

	go func() {
		_ = copyOrWarn(ctx, proxyClient, remoteConn)
		waitChan <- struct{}{}
	}()

	// Wait until one end closes the connection
	<-waitChan
}

// proxyWebSocketUpgrade handles WebSocket upgrades by creating a direct connection
// to the backend and forwarding the upgrade request/response without using HTTP transport
func (proxy *ProxyHttpServer) proxyWebSocketUpgrade(ctx *ProxyCtx, req *http.Request, clientConn io.ReadWriter) error {
	// Determine backend address and TLS requirement
	scheme := req.URL.Scheme
	backendHost := req.URL.Host
	if !strings.Contains(backendHost, ":") {
		if scheme == "https" {
			backendHost += ":443"
		} else {
			backendHost += ":80"
		}
	}

	// Create direct connection to backend
	var backendConn net.Conn
	var err error

	if scheme == "https" {
		// Use uTLS for HTTPS backends to mimic the client's TLS fingerprint
		rawConn, err := net.Dial("tcp", backendHost)
		if err != nil {
			return fmt.Errorf("failed to dial backend: %v", err)
		}

		tlsConfig := &tls.Config{
			ServerName:         req.URL.Hostname(),
			InsecureSkipVerify: true,
		}

		// Use the client's captured TLS fingerprint if available
		if ctx.ClientHelloSpec != nil {
			uConn, err := createClientHelloFrom(rawConn, ctx.ClientHelloSpec, tlsConfig)
			if err != nil {
				rawConn.Close()
				return fmt.Errorf("failed to create uTLS connection with client fingerprint: %v", err)
			}
			// Perform the TLS handshake
			if err := uConn.HandshakeContext(context.Background()); err != nil {
				uConn.Close()
				return fmt.Errorf("uTLS handshake failed: %v", err)
			}
			backendConn = uConn
		} else {
			// Fallback to standard uTLS without fingerprint if not captured
			uConn := tls.UClient(rawConn, tlsConfig, tls.HelloChrome_Auto)
			if err := uConn.HandshakeContext(context.Background()); err != nil {
				uConn.Close()
				return fmt.Errorf("uTLS handshake failed: %v", err)
			}
			backendConn = uConn
		}
	} else {
		// Plain TCP for HTTP backends
		var err error
		backendConn, err = net.Dial("tcp", backendHost)
		if err != nil {
			return fmt.Errorf("failed to dial backend: %v", err)
		}
	}

	ctx.Logf("Connected to WebSocket backend at %s", backendHost)

	// Send the HTTP upgrade request to the backend
	requestLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", req.Method, req.RequestURI)
	if _, err := io.WriteString(backendConn, requestLine); err != nil {
		return fmt.Errorf("failed to send request line: %v", err)
	}

	// Write headers (excluding hop-by-hop headers)
	for k, vv := range req.Header {
		if shouldSkipHeader(k) {
			continue
		}
		for _, v := range vv {
			if _, err := fmt.Fprintf(backendConn, "%s: %s\r\n", k, v); err != nil {
				return fmt.Errorf("failed to send header: %v", err)
			}
		}
	}

	// Set Host header if not already present
	if req.Header.Get("Host") == "" {
		if _, err := fmt.Fprintf(backendConn, "Host: %s\r\n", req.Host); err != nil {
			return fmt.Errorf("failed to send Host header: %v", err)
		}
	}

	if _, err := io.WriteString(backendConn, "\r\n"); err != nil {
		return fmt.Errorf("failed to send request terminator: %v", err)
	}

	// Read the 101 response from backend
	backendReader := bufio.NewReader(backendConn)
	resp, err := http.ReadResponse(backendReader, req)
	if err != nil {
		return fmt.Errorf("failed to read backend response: %v", err)
	}
	defer resp.Body.Close()

	ctx.Logf("Backend response status: %d", resp.StatusCode)

	// Check if backend sent 101 Switching Protocols
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Read error response body for logging
		data := make([]byte, 4096)
		resp.Body.Read(data)
		return fmt.Errorf("backend returned %d instead of 101 Switching Protocols", resp.StatusCode)
	}

	// Ensure we have Sec-WebSocket-Accept header
	if resp.Header.Get("Sec-WebSocket-Accept") == "" {
		ctx.Warnf("Backend response missing Sec-WebSocket-Accept header")
		// Compute it from our Sec-WebSocket-Key
		key := req.Header.Get("Sec-WebSocket-Key")
		if key != "" {
			resp.Header.Set("Sec-WebSocket-Accept", computeSecWebSocketAccept(key))
		}
	}

	// Write the 101 response to the client
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	if err := resp.Write(clientConn); err != nil {
		return fmt.Errorf("failed to write response to client: %v", err)
	}

	ctx.Logf("WebSocket upgrade successful, starting bidirectional tunneling")

	// Now tunnel WebSocket frames between client and backend
	// The backend connection might have read buffered data in backendReader
	// So we need to create a combined reader that includes the buffer
	backendCombined := struct {
		io.Reader
		io.Writer
	}{
		Reader: backendReader,
		Writer: backendConn,
	}

	proxy.proxyWebsocket(ctx, backendCombined, clientConn)
	return nil
}

// shouldSkipHeader checks if a header should be skipped when forwarding
func shouldSkipHeader(name string) bool {
	// Skip hop-by-hop headers and connection-specific headers
	skip := map[string]bool{
		"Connection":          true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"TE":                  true,
		"Trailers":            true,
		"Transfer-Encoding":   true,
		"Upgrade":             true,
		// Don't skip Sec-WebSocket-* headers
	}
	name = strings.ToLower(name)
	// Exception: keep Upgrade and Connection for WebSocket
	if strings.Contains(name, "websocket") || name == "upgrade" || name == "connection" {
		return false
	}
	return skip[strings.ToLower(name)]
}
