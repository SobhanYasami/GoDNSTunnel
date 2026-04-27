.PHONY: build test vet lint clean run

GO        ?= go
LDFLAGS   ?= -s -w
BUILDARGS ?= -trimpath -ldflags '$(LDFLAGS)'

build:
	$(GO) build $(BUILDARGS) -o relayvpn ./cmd/relayvpn

test:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

# Best-effort lint: requires `golangci-lint` on PATH. CI installs it
# from https://golangci-lint.run.
lint:
	@command -v golangci-lint >/dev/null || { echo "golangci-lint not installed"; exit 1; }
	golangci-lint run ./...

run: build
	./relayvpn -c config.json

clean:
	rm -f relayvpn relayvpn.exe
	rm -rf dist
