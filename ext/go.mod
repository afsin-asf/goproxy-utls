module github.com/afsin-asf/goproxy-utls/ext

go 1.25.0

require (
	github.com/elazarl/goproxy v1.8.3
	github.com/elazarl/goproxy/ext v0.0.0-20260327201742-eeb2adb11cb5
	github.com/stretchr/testify v1.11.1
	golang.org/x/net v0.51.0
	golang.org/x/text v0.35.0
)

replace github.com/afsin-asf/goproxy-utls => ../

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
