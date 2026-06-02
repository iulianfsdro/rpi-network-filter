.PHONY: build build-arm deps assets clean install

BINARY=netfilterd
BUILD_DIR=./cmd/netfilterd

# Build for current platform
build: deps assets
	go build -o $(BINARY) $(BUILD_DIR)

# Cross-compile for RPi4 (arm64). Intentionally does NOT depend on `deps`:
# `go mod tidy` needs Internet, which the deploying Mac doesn't have while
# joined to the Pi's filtered hotspot. Run `make deps` explicitly when you
# actually want to refresh go.mod/go.sum.
build-arm: assets
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BINARY)-arm64 $(BUILD_DIR)

# Download Go dependencies
deps:
	go mod tidy

# Download frontend assets
assets:
	@mkdir -p web/static/css web/static/js
	@if [ ! -s web/static/css/pico.min.css ] || [ $$(wc -c < web/static/css/pico.min.css) -lt 1000 ]; then \
		echo "Downloading Pico CSS..."; \
		curl -sLo web/static/css/pico.min.css "https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css"; \
	fi
	@if [ ! -s web/static/js/alpine.min.js ] || [ $$(wc -c < web/static/js/alpine.min.js) -lt 1000 ]; then \
		echo "Downloading Alpine.js..."; \
		curl -sLo web/static/js/alpine.min.js "https://cdn.jsdelivr.net/npm/alpinejs@3/dist/cdn.min.js"; \
	fi

# Deploy to RPi via SSH
install: build-arm
	@echo "Usage: make install RPI=pi@192.168.x.x"
	@test -n "$(RPI)" || (echo "Set RPI=user@host"; exit 1)
	scp $(BINARY)-arm64 $(RPI):/tmp/netfilterd
	ssh $(RPI) 'sudo mv /tmp/netfilterd /usr/local/bin/netfilterd && sudo systemctl restart netfilterd'

clean:
	rm -f $(BINARY) $(BINARY)-arm64
