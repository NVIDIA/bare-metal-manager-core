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
# Top-level Makefile for the rest-api/ Go services.
#
# Thin discoverable entrypoint that delegates to rest-api/Makefile.
# rest-api/Makefile continues to work directly; this file is an
# additive convenience layer.
#
# Run `make help` (default goal) for the inventory of targets.

SHELL := /bin/bash

.DEFAULT_GOAL := help

# =============================================================================
# Help (default goal)
# =============================================================================

.PHONY: help
help: ## Show this help and exit (default goal)
	@echo "Rest (Go services in rest-api/):"
	@grep -E '^rest-[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "} {printf "  %-22s %s\n", $$1, $$2}'
	@echo "  rest-api/<target>      Pass any target through to rest-api/Makefile"
	@echo ""
	@echo "  cat rest-api/Makefile  See all rest-api/ targets directly"

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
