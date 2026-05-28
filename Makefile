BINARY := phoneaccess
MODULE := github.com/KatrielMoses/PhoneAccess
DIST := dist
GO ?= go
VERSION ?= v1.0.0
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)

.PHONY: build test lint cross clean install deb rpm package release

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/phoneaccess

test:
	$(GO) test ./...

lint:
	$(GO) vet ./...

cross:
	mkdir -p $(DIST)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)_windows_amd64.exe ./cmd/phoneaccess
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)_windows_arm64.exe ./cmd/phoneaccess
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)_darwin_amd64 ./cmd/phoneaccess
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)_darwin_arm64 ./cmd/phoneaccess
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)_linux_amd64 ./cmd/phoneaccess
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)_linux_arm64 ./cmd/phoneaccess

clean:
	rm -rf $(DIST) $(BINARY) $(BINARY).exe

install:
	CGO_ENABLED=0 $(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/phoneaccess

deb:
	VERSION=$(VERSION) nfpm pkg --packager deb --target $(DIST)/$(BINARY)_linux_amd64.deb

rpm:
	VERSION=$(VERSION) nfpm pkg --packager rpm --target $(DIST)/$(BINARY)_linux_amd64.rpm

package: deb rpm

release: clean test lint cross package
