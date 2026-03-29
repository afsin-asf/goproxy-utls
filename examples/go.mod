module github.com/afsin-asf/goproxy-utls/examples

go 1.25.0

require (
	github.com/afsin-asf/goproxy-utls v1.5.0
	github.com/afsin-asf/goproxy-utls/ext v0.0.0-20250117123040-e9229c451ab8
	github.com/coder/websocket v1.8.14
	github.com/inconshreveable/go-vhost v1.0.0
)

require (
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
)

replace github.com/afsin-asf/goproxy-utls => ../

replace github.com/afsin-asf/goproxy-utls/ext => ../ext
