.PHONY: build-docker build-image build clean

DOCKER_OUTPUT ?= target/docker

# Build bloodhound binary via Docker (works on any OS)
build-docker:
	docker build \
		--platform linux/amd64 \
		-f Dockerfile.build \
		--output type=local,dest=$(DOCKER_OUTPUT) \
		.

# Build only the toolchain stage (CI cache warming)
build-image:
	docker build \
		--platform linux/amd64 \
		-f Dockerfile.build \
		--target toolchain \
		-t bloodhound-toolchain \
		.

# Native cargo build (Linux only)
build:
	cargo build --package bloodhound --release --target x86_64-unknown-linux-musl

# Clean Docker build output
clean:
	rm -rf $(DOCKER_OUTPUT)
