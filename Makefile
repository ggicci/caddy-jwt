# Requisites:
# 1. Go: https://golang.org/
# 2. xcaddy: https://github.com/caddyserver/xcaddy

default: build

GO=go
GOTEST=$(GO) test
GOCOVER=$(GO) tool cover
XCADDY=xcaddy

export CADDY_VERSION=v2.4.3

.PHONY: example
example:
	$(XCADDY) run --config example/caddy.json

.PHONY: test
test: test/cover test/report

.PHONY: test/cover
test/cover:
	$(GOTEST) -v -race -failfast -parallel 4 -cpu 4 -coverprofile main.cover.out ./...

.PHONY: test/report
test/report:
	$(GOCOVER) -html=main.cover.out
