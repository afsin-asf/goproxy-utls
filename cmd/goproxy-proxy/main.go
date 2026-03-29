package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/afsin-asf/goproxy-utls"
)

func main() {
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	// uTLS fingerprint forwarding aktif
	// (senin fork'taki aktivasyon şekline göre ayarla)

	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	fmt.Println("Proxy listening on :8888")
	log.Fatal(http.ListenAndServe(":8888", proxy))
}
