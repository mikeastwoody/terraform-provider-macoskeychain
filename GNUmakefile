# OpenTofu binary used by acceptance tests, the proof script and docs
# generation. Set TOFU=terraform to use Terraform instead.
TOFU ?= tofu

default: fmt lint install generate

build:
	go build -v ./...

# Only the provider: internal/proofsink is a test helper of the proof script.
install: build
	go install -v .

lint:
	golangci-lint run

generate:
	cd tools; TOFU=$(TOFU) go generate ./...

fmt:
	gofmt -s -w -e .

test:
	go test -v -cover -timeout=120s -parallel=10 ./...

# Acceptance tests create throwaway keychains in temporary directories and run
# OpenTofu against the provider served in-process.
testacc:
	TF_ACC=1 \
	TF_ACC_TERRAFORM_PATH="$$(command -v $(TOFU))" \
	TF_ACC_PROVIDER_NAMESPACE=hashicorp \
	TF_ACC_PROVIDER_HOST=registry.opentofu.org \
	go test -v -cover -timeout 120m ./...

# A real plan -out and apply that proves a secret reaches a write-only argument
# intact and reaches neither the plan nor the state.
prove:
	TOFU=$(TOFU) scripts/prove-no-secret-in-state.sh

.PHONY: fmt lint test testacc prove build install generate
