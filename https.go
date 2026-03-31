package goproxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	tls "github.com/refraction-networking/utls"

	"github.com/afsin-asf/goproxy-utls/internal/http1parser"
	"github.com/afsin-asf/goproxy-utls/internal/signer"
)

type ConnectActionLiteral int

const (
	ConnectAccept = iota
	ConnectReject
	ConnectMitm
	ConnectHijack
	// Deprecated: use ConnectMitm.
	ConnectHTTPMitm
	ConnectProxyAuthHijack
)

var (
	OkConnect   = &ConnectAction{Action: ConnectAccept, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	MitmConnect = &ConnectAction{Action: ConnectMitm, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	// Deprecated: use MitmConnect.
	HTTPMitmConnect = &ConnectAction{Action: ConnectHTTPMitm, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
	RejectConnect   = &ConnectAction{Action: ConnectReject, TLSConfig: TLSConfigFromCA(&GoproxyCa)}
)

var _errorRespMaxLength int64 = 500

type readBufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *readBufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// ConnectAction enables the caller to override the standard connect flow.
// When Action is ConnectHijack, it is up to the implementer to send the
// HTTP 200, or any other valid http response back to the client from within the
// Hijack func.
type ConnectAction struct {
	Action    ConnectActionLiteral
	Hijack    func(req *http.Request, client net.Conn, ctx *ProxyCtx)
	TLSConfig func(host string, ctx *ProxyCtx) (*tls.Config, error)
}

func stripPort(s string) string {
	var ix int
	if strings.Contains(s, "[") && strings.Contains(s, "]") {
		// ipv6 address example: [2606:4700:4700::1111]:443
		// strip '[' and ']'
		s = strings.ReplaceAll(s, "[", "")
		s = strings.ReplaceAll(s, "]", "")

		ix = strings.LastIndexAny(s, ":")
		if ix == -1 {
			return s
		}
	} else {
		// ipv4
		ix = strings.IndexRune(s, ':')
		if ix == -1 {
			return s
		}
	}
	return s[:ix]
}

func (proxy *ProxyHttpServer) dial(ctx *ProxyCtx, network, addr string) (c net.Conn, err error) {
	if ctx.Dialer != nil {
		return ctx.Dialer(ctx.Req.Context(), network, addr)
	}

	if proxy.Tr != nil && proxy.Tr.DialContext != nil {
		return proxy.Tr.DialContext(ctx.Req.Context(), network, addr)
	}

	// if the user didn't specify any dialer, we just use the default one,
	// provided by net package
	var d net.Dialer
	return d.DialContext(ctx.Req.Context(), network, addr)
}

func (proxy *ProxyHttpServer) connectDial(ctx *ProxyCtx, network, addr string) (c net.Conn, err error) {
	if proxy.ConnectDialWithReq == nil && proxy.ConnectDial == nil {
		return proxy.dial(ctx, network, addr)
	}

	if proxy.ConnectDialWithReq != nil {
		return proxy.ConnectDialWithReq(ctx.Req, network, addr)
	}

	return proxy.ConnectDial(network, addr)
}

type halfClosable interface {
	net.Conn
	CloseWrite() error
	CloseRead() error
}

var _ halfClosable = (*net.TCPConn)(nil)

func (proxy *ProxyHttpServer) handleHttps(w http.ResponseWriter, r *http.Request) {
	ctx := &ProxyCtx{
		Req:       r,
		Session:   atomic.AddInt64(&proxy.sess, 1),
		Proxy:     proxy,
		certStore: proxy.CertStore,
	}

	// Initialize default RoundTripper if not set by user
	if ctx.RoundTripper == nil {
		ctx.RoundTripper = RoundTripperFunc(func(req *http.Request, ctx *ProxyCtx) (*http.Response, error) {
			return ctx.Proxy.Tr.RoundTrip(req)
		})
	}

	hij, ok := w.(http.Hijacker)
	if !ok {
		panic("httpserver does not support hijacking")
	}

	proxyClient, _, e := hij.Hijack()
	if e != nil {
		panic("Cannot hijack connection " + e.Error())
	}

	ctx.Logf("Running %d CONNECT handlers", len(proxy.httpsHandlers))
	todo, host := OkConnect, r.URL.Host
	for i, h := range proxy.httpsHandlers {
		newtodo, newhost := h.HandleConnect(host, ctx)
		if newtodo != nil {
			todo, host = newtodo, newhost
			ctx.Logf("on %dth handler: %v %s", i, todo, host)
			break
		}
	}

	switch todo.Action {
	case ConnectAccept:
		if !hasPort.MatchString(host) {
			host += ":80"
		}
		targetSiteCon, err := proxy.connectDial(ctx, "tcp", host)
		if err != nil {
			ctx.Warnf("Error dialing to %s: %s", host, err.Error())
			httpError(proxyClient, ctx, err)
			return
		}
		ctx.Logf("Accepting CONNECT to %s", host)
		_, _ = proxyClient.Write([]byte("HTTP/1.0 200 Connection established\r\n\r\n"))

		targetTCP, targetOK := targetSiteCon.(halfClosable)
		proxyClientTCP, clientOK := proxyClient.(halfClosable)
		if targetOK && clientOK {
			go func() {
				var wg sync.WaitGroup
				wg.Add(2)
				go copyAndClose(ctx, targetTCP, proxyClientTCP, &wg)
				go copyAndClose(ctx, proxyClientTCP, targetTCP, &wg)
				wg.Wait()
				proxyClientTCP.Close()
				targetTCP.Close()
			}()
		} else {
			go func() {
				err := copyOrWarn(ctx, targetSiteCon, proxyClient)
				if err != nil && proxy.ConnectionErrHandler != nil {
					proxy.ConnectionErrHandler(proxyClient, ctx, err)
				}
				_ = targetSiteCon.Close()
			}()
			go func() {
				_ = copyOrWarn(ctx, proxyClient, targetSiteCon)
				_ = proxyClient.Close()
			}()
		}

	case ConnectHijack:
		todo.Hijack(r, proxyClient, ctx)

	case ConnectHTTPMitm, ConnectMitm:
		_, _ = proxyClient.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
		ctx.Logf("Received CONNECT request, mitm proxying it")

		go func() {
			readBuffer := bufio.NewReader(proxyClient)
			peek, _ := readBuffer.Peek(1)
			isTLS := len(peek) > 0 && peek[0] == _tlsRecordTypeHandshake

			var capturedHelloSpec *tls.ClientHelloSpec
			var capturedRawHello []byte

			var tlsConfig *tls.Config
			scheme := "http"
			fingerprinter := &tls.Fingerprinter{}
			var client net.Conn

			if isTLS {
				scheme = "https"
				tlsConfig = defaultTLSConfig
				if todo.TLSConfig != nil {
					var err error
					tlsConfig, err = todo.TLSConfig(host, ctx)
					if err != nil {
						httpError(proxyClient, ctx, err)
						return
					}
				}

				// Wrap client connection with ClientHello capture wrapper that includes buffering
				captureConn := newClientHelloCaptureConn(proxyClient)
				// Create a capturing buffered reader wrapper
				capturingReader := &capturingBufferedReader{
					source:      readBuffer,
					captureConn: captureConn,
				}
				// Use capturing reader with the capture connection
				bufferedConn := &readBufferedConn{Conn: captureConn, r: capturingReader}

				// Use wrapper to capture and fingerprint client TLS
				rawClientTls := tls.Server(bufferedConn, tlsConfig)
				if err := rawClientTls.HandshakeContext(context.Background()); err != nil {
					ctx.Warnf("Cannot handshake client %v %v", r.Host, err)
					return
				}

				// ✅ Capture the raw ClientHello for TLS fingerprinting
				capturedRawHello = captureConn.ClientHelloBytes()
				if capturedRawHello != nil {
					spec, err := fingerprinter.FingerprintClientHello(capturedRawHello)
					if err == nil {
						capturedHelloSpec = spec
						ctx.Logf("Captured ClientHello fingerprint (%d bytes)", len(capturedRawHello))
					} else {
						ctx.Warnf("Failed to fingerprint ClientHello: %v", err)
					}
				}

				client = rawClientTls
			} else {
				client = &readBufferedConn{Conn: proxyClient, r: readBuffer}
			}

			defer func() {
				_ = client.Close()
			}()

			clientReader := http1parser.NewRequestReader(proxy.PreventCanonicalization, client)
			for !clientReader.IsEOF() {
				req, err := clientReader.ReadRequest()
				// Create per-request context but carry over fingerprint
				reqCtx := &ProxyCtx{
					Req:             req,
					Session:         atomic.AddInt64(&proxy.sess, 1),
					Proxy:           proxy,
					UserData:        ctx.UserData,
					RoundTripper:    ctx.RoundTripper,
					ClientHelloSpec: capturedHelloSpec,
					RawClientHello:  capturedRawHello,
				}
				if err != nil && !errors.Is(err, io.EOF) {
					reqCtx.Warnf("Cannot read request from mitm'd client %v %v", r.Host, err)
				}
				if err != nil {
					return
				}

				req.RemoteAddr = r.RemoteAddr
				reqCtx.Logf("req %v", r.Host)

				if !strings.HasPrefix(req.URL.String(), scheme+"://") {
					req.URL, err = url.Parse(scheme + "://" + r.Host + req.URL.String())
				}

				if continueLoop := func(req *http.Request) bool {
					requestContext, finishRequest := context.WithCancel(req.Context())
					req = req.WithContext(requestContext)
					defer finishRequest()
					defer req.Body.Close()

					reqCtx.Req = req

					req, resp := proxy.filterRequest(req, reqCtx)
					if resp == nil {
						if req.Method == "PRI" {
							reader := clientReader.Reader()
							_, err := reader.Discard(6)
							if err != nil {
								reqCtx.Warnf("Failed to process HTTP2 client preface: %v", err)
								return false
							}
							if !proxy.AllowHTTP2 {
								reqCtx.Warnf("HTTP2 connection failed: disallowed")
								return false
							}
							tr := H2Transport{reader, client, tlsConfig, host, reqCtx}
							if _, err := tr.RoundTrip(req); err != nil {
								reqCtx.Warnf("HTTP2 connection failed: %v", err)
							} else {
								reqCtx.Logf("Exiting on EOF")
							}
							return false
						}
						if err != nil {
							if req.URL != nil {
								reqCtx.Warnf("Illegal URL %s", scheme+"://"+r.Host+req.URL.Path)
							} else {
								reqCtx.Warnf("Illegal URL %s", scheme+"://"+r.Host)
							}
							return false
						}
						if !proxy.KeepHeader {
							RemoveProxyHeaders(reqCtx, req)
						}

						// Check for WebSocket upgrade request
						if strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
							strings.ContainsAny(strings.ToLower(req.Header.Get("Connection")), "upgrade") {
							reqCtx.Logf("WebSocket upgrade request detected, proxying via uTLS")
							
							// Dial backend
							backendConn, err := proxy.dial(reqCtx, "tcp", req.Host)
							if err != nil {
								reqCtx.Warnf("Failed to dial backend for WebSocket: %v", err)
								return false
							}
							defer backendConn.Close()
							
							// Initialize TLS connection with client's fingerprint
							utlsConn, err := proxy.initializeTLSconnection(reqCtx, backendConn, defaultTLSConfig, req.Host)
							if err != nil {
								reqCtx.Warnf("Failed to initialize TLS connection for WebSocket: %v", err)
								return false
							}
							
							// Send the original WebSocket upgrade request to backend
							if err := req.Write(utlsConn); err != nil {
								reqCtx.Warnf("Failed to send WebSocket upgrade request to backend: %v", err)
								return false
							}
							
							// Read the 101 response from backend
							reader := bufio.NewReader(utlsConn)
							resp, err = http.ReadResponse(reader, req)
							if err != nil {
								reqCtx.Warnf("Failed to read WebSocket 101 response from backend: %v", err)
								return false
							}
							
							// Check if we got a 101 response
							if resp.StatusCode != http.StatusSwitchingProtocols {
								reqCtx.Warnf("Backend returned status %d instead of 101", resp.StatusCode)
								return false
							}
							
							// Write the 101 response to the client (with proper Sec-WebSocket-Accept header)
							if err := resp.Write(client); err != nil {
								reqCtx.Warnf("Failed to write WebSocket 101 response to client: %v", err)
								return false
							}
							
							// Tunnel WebSocket frames between client and backend
							proxy.proxyWebsocket(reqCtx, utlsConn, client)
							return false
						}

						resp, err = reqCtx.RoundTripper.RoundTrip(req, reqCtx)
						if err != nil {
							reqCtx.Warnf("Cannot read response from mitm'd server %v", err)
							return false
						}
						reqCtx.Logf("resp %v", resp.Status)
					}
					origBody := resp.Body
					resp = proxy.filterResponse(resp, reqCtx)
					bodyModified := resp.Body != origBody
					defer resp.Body.Close()
					if bodyModified || (resp.ContentLength <= 0 && resp.Header.Get("Content-Length") == "") {
						resp.ContentLength = -1
						resp.Header.Del("Content-Length")
						resp.TransferEncoding = []string{"chunked"}
					}

					resp.Proto = "HTTP/1.1"
					resp.ProtoMajor = 1
					resp.ProtoMinor = 1

					if isWebSocketHandshake(resp.Header) {
						reqCtx.Logf("Response looks like websocket upgrade.")
						wsConn, ok := resp.Body.(io.ReadWriter)
						if !ok {
							reqCtx.Warnf("Unable to use Websocket connection")
							return false
						}
						resp.Body = nil
						if err := resp.Write(client); err != nil {
							reqCtx.Warnf("Cannot write response header from mitm'd client: %v", err)
							return false
						}
						proxy.proxyWebsocket(reqCtx, wsConn, client)
						return false
					}

					if err := resp.Write(client); err != nil {
						reqCtx.Warnf("Cannot write response from mitm'd client: %v", err)
						return false
					}

					return true
				}(req); !continueLoop {
					return
				}
			}
			ctx.Logf("Exiting on EOF")
		}()
	case ConnectProxyAuthHijack:
		_, _ = proxyClient.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n"))
		todo.Hijack(r, proxyClient, ctx)

	case ConnectReject:
		if ctx.Resp != nil {
			if err := ctx.Resp.Write(proxyClient); err != nil {
				ctx.Warnf("Cannot write response that reject http CONNECT: %v", err)
			}
		}
		_ = proxyClient.Close()
	}
}

func httpError(w io.WriteCloser, ctx *ProxyCtx, err error) {
	if ctx.Proxy.ConnectionErrHandler != nil {
		ctx.Proxy.ConnectionErrHandler(w, ctx, err)
	} else {
		errorMessage := err.Error()
		errStr := fmt.Sprintf(
			"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s",
			len(errorMessage),
			errorMessage,
		)
		if _, err := io.WriteString(w, errStr); err != nil {
			ctx.Warnf("Error responding to client: %s", err)
		}
	}
	if err := w.Close(); err != nil {
		ctx.Warnf("Error closing client connection: %s", err)
	}
}

func copyOrWarn(ctx *ProxyCtx, dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	if err != nil && errors.Is(err, net.ErrClosed) {
		// Discard closed connection errors
		err = nil
	} else if err != nil {
		ctx.Warnf("Error copying to client: %s", err)
	}
	return err
}

func copyAndClose(ctx *ProxyCtx, dst, src halfClosable, wg *sync.WaitGroup) {
	_, err := io.Copy(dst, src)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		ctx.Warnf("Error copying to client: %s", err.Error())
	}

	_ = dst.CloseWrite()
	_ = src.CloseRead()
	wg.Done()
}

func dialerFromEnv(proxy *ProxyHttpServer) func(network, addr string) (net.Conn, error) {
	httpsProxy := os.Getenv("HTTPS_PROXY")
	if httpsProxy == "" {
		httpsProxy = os.Getenv("https_proxy")
	}
	if httpsProxy == "" {
		return nil
	}
	return proxy.NewConnectDialToProxy(httpsProxy)
}

func (proxy *ProxyHttpServer) NewConnectDialToProxy(httpsProxy string) func(network, addr string) (net.Conn, error) {
	return proxy.NewConnectDialToProxyWithHandler(httpsProxy, nil)
}

func (proxy *ProxyHttpServer) NewConnectDialToProxyWithHandler(
	httpsProxy string,
	connectReqHandler func(req *http.Request),
) func(network, addr string) (net.Conn, error) {
	u, err := url.Parse(httpsProxy)
	if err != nil {
		return nil
	}
	if u.Scheme == "" || u.Scheme == "http" || u.Scheme == "ws" {
		if !strings.ContainsRune(u.Host, ':') {
			u.Host += ":80"
		}
		return func(network, addr string) (net.Conn, error) {
			connectReq := &http.Request{
				Method: http.MethodConnect,
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			if connectReqHandler != nil {
				connectReqHandler(connectReq)
			}
			c, err := proxy.dial(&ProxyCtx{Req: &http.Request{}}, network, u.Host)
			if err != nil {
				return nil, err
			}
			_ = connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				resp, err := io.ReadAll(io.LimitReader(resp.Body, _errorRespMaxLength))
				if err != nil {
					return nil, err
				}
				_ = c.Close()
				return nil, errors.New("proxy refused connection" + string(resp))
			}
			return c, nil
		}
	}
	if u.Scheme == "https" || u.Scheme == "wss" {
		if !strings.ContainsRune(u.Host, ':') {
			u.Host += ":443"
		}
		return func(network, addr string) (net.Conn, error) {
			ctx := &ProxyCtx{Req: &http.Request{}}
			c, err := proxy.dial(ctx, network, u.Host)
			if err != nil {
				return nil, err
			}

			c, err = proxy.initializeTLSconnection(ctx, c, proxy.TLSClientConfig, u.Host)
			if err != nil {
				return nil, err
			}

			connectReq := &http.Request{
				Method: http.MethodConnect,
				URL:    &url.URL{Opaque: addr},
				Host:   addr,
				Header: make(http.Header),
			}
			if connectReqHandler != nil {
				connectReqHandler(connectReq)
			}
			_ = connectReq.Write(c)
			// Read response.
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, connectReq)
			if err != nil {
				_ = c.Close()
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				body, err := io.ReadAll(io.LimitReader(resp.Body, _errorRespMaxLength))
				if err != nil {
					return nil, err
				}
				_ = c.Close()
				return nil, errors.New("proxy refused connection" + string(body))
			}
			return c, nil
		}
	}
	return nil
}

func TLSConfigFromCA(ca *tls.Certificate) func(host string, ctx *ProxyCtx) (*tls.Config, error) {
	return func(host string, ctx *ProxyCtx) (*tls.Config, error) {
		var err error
		var cert *tls.Certificate

		hostname := stripPort(host)
		config := defaultTLSConfig.Clone()
		ctx.Logf("signing for %s", stripPort(host))

		genCert := func() (*tls.Certificate, error) {
			return signer.SignHost(*ca, []string{hostname})
		}
		if ctx.certStore != nil {
			cert, err = ctx.certStore.Fetch(hostname, genCert)
		} else {
			cert, err = genCert()
		}

		if err != nil {
			ctx.Warnf("Cannot sign host certificate with provided CA: %s", err)
			return nil, err
		}

		// Replace the certificate list with only the generated certificate
		// (not appended to defaultTLSConfig.Certificates which contains the CA cert)
		config.Certificates = []tls.Certificate{*cert}
		return config, nil
	}
}

func (proxy *ProxyHttpServer) initializeTLSconnection(
	ctx *ProxyCtx,
	targetConn net.Conn,
	tlsConfig *tls.Config,
	addr string,
) (net.Conn, error) {
	// Infer target ServerName, it's a copy of implementation inside tls.Dial()
	if tlsConfig.ServerName == "" {
		colonPos := strings.LastIndex(addr, ":")
		if colonPos == -1 {
			colonPos = len(addr)
		}
		hostname := addr[:colonPos]
		// Make a copy to avoid polluting argument or default.
		c := tlsConfig.Clone()
		c.ServerName = hostname
		tlsConfig = c
	}

	// Use the incoming client's TLS fingerprint if captured via ClientHelloSpec
	if ctx.ClientHelloSpec != nil {
		// Use ApplyPreset with the captured fingerprint spec
		uConn, err := createClientHelloFrom(targetConn, ctx.ClientHelloSpec, tlsConfig)
		if err != nil {
			ctx.Warnf("Failed to apply captured ClientHello spec: %v, falling back to default", err)
			// Fall back to default Chrome
			uConn := tls.UClient(targetConn, tlsConfig, tls.HelloChrome_Auto)
			if err := uConn.HandshakeContext(ctx.Req.Context()); err != nil {
				return nil, err
			}
			return uConn, nil
		}
		ctx.Logf("Using captured ClientHello fingerprint for outgoing connection")
		if err := uConn.HandshakeContext(ctx.Req.Context()); err != nil {
			return nil, err
		}
		return uConn, nil
	}

	// Fall back to default Chrome fingerprint if no capture
	ctx.Logf("Using default Chrome fingerprint for outgoing connection")
	uConn := tls.UClient(targetConn, tlsConfig, tls.HelloChrome_Auto)
	if err := uConn.HandshakeContext(ctx.Req.Context()); err != nil {
		return nil, err
	}
	return uConn, nil
}
