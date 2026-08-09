BINARY := bin/aku-cinta-vpn
PACKAGE := ./cmd/aku-cinta-vpn
VERSION ?= 0.1.0

.PHONY: all build test vet fmt key clean setup-demo clean-demo

all: build

build:
	mkdir -p bin
	go build -trimpath -ldflags "-X main.version=$(VERSION)" -o $(BINARY) $(PACKAGE)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

key: build
	./$(BINARY) --generate-key vpn.key

clean:
	rm -f -- $(BINARY)
	-rmdir bin

setup-demo:
	./scripts/setup-netns.sh

clean-demo:
	./scripts/cleanup-netns.sh
