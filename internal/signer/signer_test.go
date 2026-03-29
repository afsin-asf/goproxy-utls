package signer_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	utlstls "github.com/refraction-networking/utls"

	"github.com/afsin-asf/goproxy-utls"
	"github.com/afsin-asf/goproxy-utls/internal/signer"
)

func orFatal(t *testing.T, msg string, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(msg, err)
	}
}

type ConstantHanlder string

func (h ConstantHanlder) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	_, _ = io.WriteString(w, string(h))
}

func testSignerX509(t *testing.T, ca utlstls.Certificate) {
	t.Helper()
	cert, err := signer.SignHost(ca, []string{"example.com", "1.1.1.1", "localhost"})
	orFatal(t, "singHost", err)
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	orFatal(t, "ParseCertificate", err)
	certpool := x509.NewCertPool()
	certpool.AddCert(ca.Leaf)
	orFatal(t, "VerifyHostname", cert.Leaf.VerifyHostname("example.com"))
	orFatal(t, "CheckSignatureFrom", cert.Leaf.CheckSignatureFrom(ca.Leaf))
	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "example.com",
		Roots:   certpool,
	})
	orFatal(t, "Verify", err)
}

func testSignerTLS(t *testing.T, ca utlstls.Certificate) {
	t.Helper()
	cert, err := signer.SignHost(ca, []string{"example.com", "1.1.1.1", "localhost"})
	orFatal(t, "singHost", err)
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	orFatal(t, "ParseCertificate", err)
	expected := "key verifies with Go"
	server := httptest.NewUnstartedServer(ConstantHanlder(expected))
	defer server.Close()
	
	// Convert utlstls.Certificate back to crypto/tls.Certificate for httptest
	cryptoCert := tls.Certificate{
		Certificate: cert.Certificate,
		PrivateKey:  cert.PrivateKey,
		Leaf:        cert.Leaf,
	}
	cryptoCa := tls.Certificate{
		Certificate: ca.Certificate,
		PrivateKey:  ca.PrivateKey,
		Leaf:        ca.Leaf,
	}
	
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{cryptoCert, cryptoCa},
		MinVersion:   tls.VersionTLS12,
	}
	server.StartTLS()
	certpool := x509.NewCertPool()
	certpool.AddCert(ca.Leaf)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: certpool},
	}
	asLocalhost := strings.ReplaceAll(server.URL, "127.0.0.1", "localhost")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, asLocalhost, nil)
	orFatal(t, "NewRequest", err)
	resp, err := tr.RoundTrip(req)
	orFatal(t, "RoundTrip", err)
	txt, err := io.ReadAll(resp.Body)
	orFatal(t, "io.ReadAll", err)
	if string(txt) != expected {
		t.Errorf("Expected '%s' got '%s'", expected, string(txt))
	}
}

func TestSignerRsaTls(t *testing.T) {
	testSignerTLS(t, goproxy.GoproxyCa)
}

func TestSignerRsaX509(t *testing.T) {
	testSignerX509(t, goproxy.GoproxyCa)
}

func TestSignerEcdsaTls(t *testing.T) {
	testSignerTLS(t, EcdsaCa)
}

func TestSignerEcdsaX509(t *testing.T) {
	testSignerX509(t, EcdsaCa)
}

func BenchmarkSignRsa(b *testing.B) {
	var cert *utlstls.Certificate
	var err error
	for n := 0; n < b.N; n++ {
		cert, err = signer.SignHost(goproxy.GoproxyCa, []string{"example.com", "1.1.1.1", "localhost"})
	}
	_ = cert
	_ = err
}

func BenchmarkSignEcdsa(b *testing.B) {
	var cert *utlstls.Certificate
	var err error
	for n := 0; n < b.N; n++ {
		cert, err = signer.SignHost(EcdsaCa, []string{"example.com", "1.1.1.1", "localhost"})
	}
	_ = cert
	_ = err
}

//
// Eliptic Curve certificate and key for testing
//

var EcdsaCaCert = []byte(`-----BEGIN CERTIFICATE-----
MIICGDCCAb8CFEkSgqYhlT0+Yyr9anQNJgtclTL0MAoGCCqGSM49BAMDMIGOMQsw
CQYDVQQGEwJJTDEPMA0GA1UECAwGQ2VudGVyMQwwCgYDVQQHDANMb2QxEDAOBgNV
BAoMB0dvUHJveHkxEDAOBgNVBAsMB0dvUHJveHkxGjAYBgNVBAMMEWdvcHJveHku
Z2l0aHViLmlvMSAwHgYJKoZIhvcNAQkBFhFlbGF6YXJsQGdtYWlsLmNvbTAeFw0x
OTA1MDcxMTUwMThaFw0zOTA1MDIxMTUwMThaMIGOMQswCQYDVQQGEwJJTDEPMA0G
A1UECAwGQ2VudGVyMQwwCgYDVQQHDANMb2QxEDAOBgNVBAoMB0dvUHJveHkxEDAO
BgNVBAsMB0dvUHJveHkxGjAYBgNVBAMMEWdvcHJveHkuZ2l0aHViLmlvMSAwHgYJ
KoZIhvcNAQkBFhFlbGF6YXJsQGdtYWlsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABDlH4YrdukPFAjbO8x+gR9F8ID7eCU8Orhba/MIblSRrRVedpj08lK+2
svyoAcrcDsynClO9aQtsC9ivZ+Pmr3MwCgYIKoZIzj0EAwMDRwAwRAIgGRSSJVSE
1b1KVU0+w+SRtnR5Wb7jkwnaDNxQ3c3FXoICIBJV/l1hFM7mbd68Oi5zLq/4ZsrL
98Bb3nddk2xys6a9
-----END CERTIFICATE-----`)

var EcdsaCaKey = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEsc8m+2aZfagnesg
qMgXe8ph4LtVu2VOUYhHttuEDsChRANCAAQ5R+GK3bpDxQI2zvMfoEfRfCA+3glP
Dq4W2vzCG5Uka0VXnaY9PJSvtrL8qAHK3A7MpwpTvWkLbAvYr2fj5q9z
-----END PRIVATE KEY-----`)

var ecdsaCaTmp, ecdsaCaErr = tls.X509KeyPair(EcdsaCaCert, EcdsaCaKey)

// EcdsaCa is converted to utlstls.Certificate for compatibility with SignHost
var EcdsaCa utlstls.Certificate

func init() {
	if ecdsaCaErr != nil {
		panic("Error parsing ecdsa CA " + ecdsaCaErr.Error())
	}
	// Convert from crypto/tls.Certificate to utlstls.Certificate
	EcdsaCa = utlstls.Certificate{
		Certificate: ecdsaCaTmp.Certificate,
		PrivateKey:  ecdsaCaTmp.PrivateKey,
		Leaf:        ecdsaCaTmp.Leaf,
	}
	var err error
	if EcdsaCa.Leaf, err = x509.ParseCertificate(EcdsaCa.Certificate[0]); err != nil {
		panic("Error parsing ecdsa CA " + err.Error())
	}
}
