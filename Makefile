#
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Top-level Makefile for selected Core workflows and the rest-api/ Go services.
#
# Thin discoverable entrypoint that delegates to cargo-make and
# rest-api/Makefile. Both underlying entrypoints continue to work directly;
# this file is an additive convenience layer.
#
# Run `make help` (default goal) for the inventory of targets.

SHELL := /bin/bash

.DEFAULT_GOAL := help

# =============================================================================
# Help (default goal)
# =============================================================================

.PHONY: help
help: ## Show this help and exit (default goal)
	@echo "Getting started (fresh build host):"
	@grep -E '^bootstrap:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "} {printf "  %-26s %s\n", $$1, $$2}'
	@echo ""
	@echo "Container images (build from a clean clone):"
	@grep -E '^images[a-zA-Z0-9_-]*:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "} {printf "  %-26s %s\n", $$1, $$2}'
	@echo ""
	@echo "Core (Rust):"
	@grep -E '^core/[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "} {printf "  %-26s %s\n", $$1, $$2}'
	@echo ""
	@echo "Rest (Go services in rest-api/):"
	@grep -E '^rest-[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "} {printf "  %-26s %s\n", $$1, $$2}'
	@echo "  rest-api/<target>          Pass any target through to rest-api/Makefile"
	@echo ""
	@echo "  cat rest-api/Makefile      See all rest-api/ targets directly"

# =============================================================================
# Core (Rust; delegate to cargo-make)
# =============================================================================

.PHONY: core/check-isolated-package-builds
core/check-isolated-package-builds: ## Check each Rust package independently with default features
	cargo make --no-workspace check-isolated-package-builds

# =============================================================================
# Getting started (build host setup)
# =============================================================================

.PHONY: bootstrap

bootstrap: ## Set up an Ubuntu/Debian build host: apt deps, rustup, submodules, docker, multi-arch emulation, cargo tooling (run once)
	./scripts/setup-build-host.sh

# =============================================================================
# Container images (single onboarding build)
# =============================================================================
# Build NICo container images from a clean clone. Run from the repo root on an
# Ubuntu build host (see docs/manuals/building_nico_containers.md for the host
# prerequisites: docker, mkosi, rust, cargo-make, ...). Every base image is
# public (rust / debian / golang + nvcr.io/nvidia/distroless), so no internal
# registry access is required.
#
#   make images        Build the deployable service stack: NICo Core + REST images
#   make images-all    Build everything: the stack plus machine-validation and
#                       boot-artifact images (needs the full mkosi build host)
#   make images-core   NICo Core image (nico) only
#   make images-rest   REST service images only
#
# Images are pushed as amd64/arm64 manifests at
# $(IMAGE_REGISTRY)/<name>:$(IMAGE_TAG). Override IMAGE_REGISTRY and IMAGE_TAG to
# publish under your own registry/tag (defaults match rest-api/).

IMAGE_REGISTRY ?= localhost:5000
IMAGE_TAG ?= latest
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
CI_COMMIT_SHORT_SHA ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LOCAL_REGISTRY_CONTAINER ?= nico-build-registry
BOOT_ARTIFACTS_RUNTIME_IMAGE ?= docker.io/library/alpine:3.20.10@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

# Intermediate base containers the Core and machine-validation images build FROM.
CORE_BUILD_CONTAINER_AMD64 ?= $(IMAGE_REGISTRY)/nico-buildcontainer:$(IMAGE_TAG)-amd64
CORE_BUILD_CONTAINER_ARM64 ?= $(IMAGE_REGISTRY)/nico-buildcontainer:$(IMAGE_TAG)-arm64
CORE_RUNTIME_CONTAINER_AMD64 ?= $(IMAGE_REGISTRY)/nico-runtime-container:$(IMAGE_TAG)-amd64
CORE_RUNTIME_CONTAINER_ARM64 ?= $(IMAGE_REGISTRY)/nico-runtime-container:$(IMAGE_TAG)-arm64
CORE_IMAGE_AMD64 := $(IMAGE_REGISTRY)/nico:$(IMAGE_TAG)-amd64
CORE_IMAGE_ARM64 := $(IMAGE_REGISTRY)/nico:$(IMAGE_TAG)-arm64
MACHINE_VALIDATION_IMAGE_AMD64 := $(IMAGE_REGISTRY)/machine-validation:$(IMAGE_TAG)-amd64
MACHINE_VALIDATION_IMAGE_ARM64 := $(IMAGE_REGISTRY)/machine-validation:$(IMAGE_TAG)-arm64
BOOT_ARTIFACTS_X86_IMAGE_AMD64 := $(IMAGE_REGISTRY)/boot-artifacts-x86_64:$(IMAGE_TAG)-amd64
BOOT_ARTIFACTS_X86_IMAGE_ARM64 := $(IMAGE_REGISTRY)/boot-artifacts-x86_64:$(IMAGE_TAG)-arm64
BOOT_ARTIFACTS_BFB_IMAGE_AMD64 := $(IMAGE_REGISTRY)/boot-artifacts-aarch64:$(IMAGE_TAG)-amd64
BOOT_ARTIFACTS_BFB_IMAGE_ARM64 := $(IMAGE_REGISTRY)/boot-artifacts-aarch64:$(IMAGE_TAG)-arm64

.PHONY: images images-all images-registry images-base images-core images-rest \
        images-machine-validation images-boot-artifacts images-bfb

images: images-core images-rest ## Build the deployable service stack (NICo Core + REST images)
	@echo ""
	@echo "Deployable multi-arch images pushed under $(IMAGE_REGISTRY) (tag: $(IMAGE_TAG)):"
	@echo "  $(IMAGE_REGISTRY)/nico:$(IMAGE_TAG)   (NICo Core)"
	@echo "  $(IMAGE_REGISTRY)/nico-rest-*:$(IMAGE_TAG)       (REST services)"

images-all: images images-machine-validation images-boot-artifacts images-bfb ## Build every image (stack + machine validation + boot artifacts; needs an mkosi build host)

images-registry:
	@if [ "$(IMAGE_REGISTRY)" = "localhost:5000" ] && ! curl -fsS http://localhost:5000/v2/ >/dev/null 2>&1; then \
		if docker inspect $(LOCAL_REGISTRY_CONTAINER) >/dev/null 2>&1; then \
			docker start $(LOCAL_REGISTRY_CONTAINER); \
		else \
			docker run -d --rm --name $(LOCAL_REGISTRY_CONTAINER) -p 5000:5000 registry:2; \
		fi; \
	fi

images-base: images-registry ## Build and push the amd64 + arm64 Core base containers
	docker buildx build --platform linux/amd64 --push --file dev/docker/Dockerfile.build-container-x86_64 -t $(CORE_BUILD_CONTAINER_AMD64) .
	docker buildx build --platform linux/arm64 --push --file dev/docker/Dockerfile.build-container-aarch64 -t $(CORE_BUILD_CONTAINER_ARM64) .
	docker buildx build --platform linux/amd64 --push --file dev/docker/Dockerfile.runtime-container-x86_64 -t $(CORE_RUNTIME_CONTAINER_AMD64) .
	docker buildx build --platform linux/arm64 --push --file dev/docker/Dockerfile.runtime-container-aarch64 -t $(CORE_RUNTIME_CONTAINER_ARM64) .

images-core: images-base ## Build the NICo Core image (nico)
	docker buildx build --platform linux/amd64 --push \
		--build-arg CONTAINER_BUILD_X86_64=$(CORE_BUILD_CONTAINER_AMD64) \
		--build-arg CONTAINER_RUNTIME_X86_64=$(CORE_RUNTIME_CONTAINER_AMD64) \
		--build-arg VERSION=$(VERSION) \
		--build-arg CI_COMMIT_SHORT_SHA=$(CI_COMMIT_SHORT_SHA) \
		--file dev/docker/Dockerfile.release-container-sa-x86_64 \
		-t $(CORE_IMAGE_AMD64) .
	docker buildx build --platform linux/arm64 --push \
		--build-arg CONTAINER_BUILD_AARCH64=$(CORE_BUILD_CONTAINER_ARM64) \
		--build-arg CONTAINER_RUNTIME_AARCH64=$(CORE_RUNTIME_CONTAINER_ARM64) \
		--build-arg VERSION=$(VERSION) \
		--build-arg CI_COMMIT_SHORT_SHA=$(CI_COMMIT_SHORT_SHA) \
		--file dev/docker/Dockerfile.release-container-aarch64 \
		-t $(CORE_IMAGE_ARM64) .
	docker buildx imagetools create -t $(IMAGE_REGISTRY)/nico:$(IMAGE_TAG) \
		$(CORE_IMAGE_AMD64) $(CORE_IMAGE_ARM64)

images-rest: images-registry ## Build the REST service images (api, workflow, site-manager, site-agent, db, cert-manager, flow, psm, nsm)
	$(MAKE) -C rest-api docker-build IMAGE_REGISTRY=$(IMAGE_REGISTRY) IMAGE_TAG=$(IMAGE_TAG)

images-machine-validation: images-base ## Build the machine-validation runner + config images
	docker buildx build --platform linux/amd64 --load --build-arg CONTAINER_RUNTIME_X86_64=$(CORE_RUNTIME_CONTAINER_AMD64) \
		-t machine-validation-runner:$(IMAGE_TAG) \
		--file dev/docker/Dockerfile.machine-validation-runner .
	mkdir -p crates/machine-validation/images
	docker save --output crates/machine-validation/images/machine-validation-runner.tar machine-validation-runner:$(IMAGE_TAG)
	docker buildx build --platform linux/amd64 --push --build-arg CONTAINER_RUNTIME_X86_64=$(CORE_RUNTIME_CONTAINER_AMD64) \
		-t $(MACHINE_VALIDATION_IMAGE_AMD64) \
		--file dev/docker/Dockerfile.machine-validation-config .
	docker buildx build --platform linux/arm64 --push --build-arg CONTAINER_RUNTIME_AARCH64=$(CORE_RUNTIME_CONTAINER_ARM64) \
		-t $(MACHINE_VALIDATION_IMAGE_ARM64) \
		--file dev/docker/Dockerfile.machine-validation-config-aarch64 .
	docker buildx imagetools create -t $(IMAGE_REGISTRY)/machine-validation:$(IMAGE_TAG) \
		$(MACHINE_VALIDATION_IMAGE_AMD64) $(MACHINE_VALIDATION_IMAGE_ARM64)

images-boot-artifacts: images-registry ## Build the x86 boot-artifact image (requires mkosi + rust toolchain on the host)
	cargo make --cwd pxe --env SA_ENABLEMENT=1 build-boot-artifacts-x86-host-sa
	docker buildx build --platform linux/amd64 --push --build-arg CONTAINER_RUNTIME_X86_64=$(BOOT_ARTIFACTS_RUNTIME_IMAGE) \
		-t $(BOOT_ARTIFACTS_X86_IMAGE_AMD64) \
		--file dev/docker/Dockerfile.release-artifacts-x86_64 .
	docker buildx build --platform linux/arm64 --push --build-arg CONTAINER_RUNTIME_X86_64=$(BOOT_ARTIFACTS_RUNTIME_IMAGE) \
		-t $(BOOT_ARTIFACTS_X86_IMAGE_ARM64) \
		--file dev/docker/Dockerfile.release-artifacts-x86_64 .
	docker buildx imagetools create -t $(IMAGE_REGISTRY)/boot-artifacts-x86_64:$(IMAGE_TAG) \
		$(BOOT_ARTIFACTS_X86_IMAGE_AMD64) $(BOOT_ARTIFACTS_X86_IMAGE_ARM64)

images-bfb: images-registry ## Build the aarch64 DPU BFB boot-artifact image (cross-arch; requires mkosi + aarch64 toolchain)
	cargo make --cwd pxe --env SA_ENABLEMENT=1 build-boot-artifacts-bfb-sa
	docker buildx build --platform linux/amd64 --push --build-arg CONTAINER_RUNTIME_AARCH64=$(BOOT_ARTIFACTS_RUNTIME_IMAGE) \
		-t $(BOOT_ARTIFACTS_BFB_IMAGE_AMD64) \
		--file dev/docker/Dockerfile.release-artifacts-aarch64 .
	docker buildx build --platform linux/arm64 --push --build-arg CONTAINER_RUNTIME_AARCH64=$(BOOT_ARTIFACTS_RUNTIME_IMAGE) \
		-t $(BOOT_ARTIFACTS_BFB_IMAGE_ARM64) \
		--file dev/docker/Dockerfile.release-artifacts-aarch64 .
	docker buildx imagetools create -t $(IMAGE_REGISTRY)/boot-artifacts-aarch64:$(IMAGE_TAG) \
		$(BOOT_ARTIFACTS_BFB_IMAGE_AMD64) $(BOOT_ARTIFACTS_BFB_IMAGE_ARM64)

# =============================================================================
# Rest (delegate to rest-api/Makefile)
# =============================================================================

.PHONY: rest-build rest-test rest-lint rest-fmt rest-clean \
        rest-docker-build rest-docker-build-local rest-helm-lint \
        rest-kind-reset

rest-build: ## Build all rest-api Go binaries into rest-api/build/binaries/
	$(MAKE) -C rest-api build

rest-test: ## Run all rest-api unit tests (auto-manages postgres + mock servers)
	$(MAKE) -C rest-api test

rest-lint: ## Lint rest-api: go vet + golangci-lint + revive
	$(MAKE) -C rest-api lint-go

rest-fmt: ## go fmt check on rest-api (fails if tree changed)
	$(MAKE) -C rest-api fmt-go

rest-clean: ## Tear down test postgres, mocks, kind, and remove rest build artifacts
	$(MAKE) -C rest-api clean

rest-docker-build: ## Build production docker images for rest services
	$(MAKE) -C rest-api docker-build

rest-docker-build-local: ## Build local-dev docker images for rest services
	$(MAKE) -C rest-api docker-build-local

rest-helm-lint: ## helm lint the rest umbrella and site-agent charts
	$(MAKE) -C rest-api helm-lint

rest-kind-reset: ## Spin up the local kind dev cluster: cluster + cert-manager + postgres + temporal + keycloak + helm app deploy (~10 min)
	$(MAKE) -C rest-api kind-reset

# Pattern-rule escape hatch: pass ANY target through to rest-api/Makefile.
# Usage:
#   make rest-api/test-api
#   make rest-api/kind-reset
#   make rest-api/generate-sdk
rest-api/%:
	$(MAKE) -C rest-api $*

proto-breaking:
	@echo "Checking for proto breaking changes..."
	@if ! command -v buf >/dev/null 2>&1; then \
		echo "buf is not installed. Please install buf: https://buf.build/docs/installation"; \
		exit 1; \
	fi
	buf breaking crates/rpc/proto --against 'https://github.com/NVIDIA/infra-controller.git#branch=main,subdir=crates/rpc/proto'

openapi-breaking:
	@echo "Checking for openapi breaking changes..."
	@if ! command -v oasdiff >/dev/null 2>&1; then \
		echo "oasdiff is not installed. Please install oasdiff: https://github.com/oasdiff/oasdiff"; \
		exit 1; \
	fi
	oasdiff breaking <(git show origin/main:rest-api/openapi/spec.yaml) rest-api/openapi/spec.yaml --fail-on ERR
