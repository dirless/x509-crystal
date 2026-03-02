SHELL      := /bin/bash
GO         := go

LIB_NAME   := libx509.so
HEADER_OUT := libx509.h
GO_DIR     := go

DOCKER       := docker
DOCKER_IMAGE := x509-crystal-builder
GO_VERSION   := 1.21.13

.PHONY: all build docker-build clean test

all: build

# Local build — requires Go >= 1.21 on PATH
build:
	@echo "==> Building $(LIB_NAME) (local)..."
	cd $(GO_DIR) && \
		CGO_ENABLED=1 $(GO) build \
			-buildmode=c-shared \
			-o ../$(LIB_NAME) \
			.
	@echo "==> Done: $(LIB_NAME)"

# AL2023 build — produces an .so compatible with AL2023/RPM targets.
# Output lands in dist/ so it's clearly separate from any local build.
docker-build:
	@echo "==> Building $(LIB_NAME) inside Amazon Linux 2023..."
	@mkdir -p dist
	$(DOCKER) build \
		--build-arg GO_VERSION=$(GO_VERSION) \
		-t $(DOCKER_IMAGE) \
		-f Dockerfile.build \
		.
	$(DOCKER) run --rm \
		-v "$(CURDIR)/dist":/output \
		$(DOCKER_IMAGE) \
		cp /build/$(LIB_NAME) /output/$(LIB_NAME)
	@echo "==> Done: dist/$(LIB_NAME)"

# Run Go unit tests (pure Go, no shared library required)
test-go:
	@echo "==> Running Go tests..."
	cd $(GO_DIR) && CGO_ENABLED=1 $(GO) test -v -race ./...

# Run Crystal specs (requires libx509.so to be built first)
test-crystal: build
	@echo "==> Running Crystal specs..."
	crystal spec

# Run all tests
test: test-go test-crystal

clean:
	rm -f $(LIB_NAME) $(HEADER_OUT)
	rm -rf dist/
