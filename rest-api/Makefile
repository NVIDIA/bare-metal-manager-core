# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

.PHONY: test postgres-up postgres-down ensure-postgres postgres-wait clean check-source-headers fix-source-headers
.PHONY: build docker-build docker-build-local
.PHONY: test-ipam test-site-agent test-site-manager test-workflow test-db test-api test-auth test-common test-cert-manager test-site-workflow test-flow migrate core-mock-server-build core-mock-server-start core-mock-server-stop flow-mock-server-build flow-mock-server-start flow-mock-server-stop
.PHONY: validate-openapi preview-openapi generate-client
.PHONY: pre-commit-install pre-commit-run pre-commit-update

# Build configuration
BUILD_DIR := build/binaries
IMAGE_REGISTRY := localhost:5000
IMAGE_TAG := latest
DOCKERFILE_DIR := docker/production

# PostgreSQL container configuration
POSTGRES_CONTAINER_NAME := project-test
POSTGRES_PORT := 30432
POSTGRES_USER := postgres
POSTGRES_PASSWORD := postgres
POSTGRES_DB := nicotest
POSTGRES_IMAGE := postgres:14.4-alpine

# Helm chart configuration (for kind-reset-helm / helm-* targets)
UMBRELLA_CHART := helm/charts/nico-rest
SITE_AGENT_CHART := helm/charts/nico-rest-site-agent

HELM_SET := --set global.image.repository=$(IMAGE_REGISTRY) \
	--set global.image.tag=$(IMAGE_TAG) \
	--set global.image.pullPolicy=Never

HELM_SET_KEYCLOAK := --set nico-rest-api.config.keycloak.enabled=true \
	--set nico-rest-api.config.keycloak.baseURL=http://keycloak:8082 \
	--set nico-rest-api.config.keycloak.externalBaseURL=http://localhost:8082 \
	--set nico-rest-api.config.keycloak.realm=nico-dev \
	--set nico-rest-api.config.keycloak.clientID=nico-api \
	--set nico-rest-api.config.keycloak.serviceAccount=true

# Tuning flags trade durability for speed. Safe because the container is
# ephemeral (--rm) and the database is recreated for every test run.
postgres-up:
	docker run -d --rm \
		--name $(POSTGRES_CONTAINER_NAME) \
		-p $(POSTGRES_PORT):5432 \
		-e POSTGRES_USER=$(POSTGRES_USER) \
		-e POSTGRES_PASSWORD=$(POSTGRES_PASSWORD) \
		-e POSTGRES_DB=$(POSTGRES_DB) \
		$(POSTGRES_IMAGE) \
		-c fsync=off \
		-c synchronous_commit=off \
		-c full_page_writes=off \
		-c wal_level=minimal \
		-c max_wal_senders=0

postgres-down:
	-docker rm -f $(POSTGRES_CONTAINER_NAME)

clean:
	@echo "Cleaning up test resources..."
	-$(MAKE) postgres-down
	-$(MAKE) core-mock-server-stop
	-$(MAKE) flow-mock-server-stop
	@echo "Stopping kind cluster..."
	-$(MAKE) kind-down
	@echo "Stopping colima..."
	-colima stop
	@echo "Removing build artifacts..."
	-rm -rf $(BUILD_DIR)
	-rm -rf build
	-rm -f db/cmd/migrations/migrations
	@echo "Clean complete"

check-source-headers:
	python3 scripts/check_source_headers.py

fix-source-headers:
	python3 scripts/check_source_headers.py --fix

ensure-postgres:
	@docker inspect $(POSTGRES_CONTAINER_NAME) > /dev/null 2>&1 || $(MAKE) postgres-up
	@$(MAKE) postgres-wait

postgres-wait:
	@until docker exec $(POSTGRES_CONTAINER_NAME) psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -c "SELECT 1" > /dev/null 2>&1; do :; done

migrate:
	docker exec $(POSTGRES_CONTAINER_NAME) psql -U $(POSTGRES_USER) -d $(POSTGRES_DB) -c "CREATE EXTENSION IF NOT EXISTS pg_trgm;"
	cd db/cmd/migrations && go build -o migrations .
	PGHOST=localhost \
	PGPORT=$(POSTGRES_PORT) \
	PGDATABASE=$(POSTGRES_DB) \
	PGUSER=$(POSTGRES_USER) \
	PGPASSWORD=$(POSTGRES_PASSWORD) \
	./db/cmd/migrations/migrations db init_migrate

fmt-go:
	go fmt ./...
	@if git diff --quiet; then \
		echo "go fmt was clean"; \
	else \
		echo "go fmt was unclean. Please commit the changes."; \
		exit 1; \
	fi

lint-go:
	go vet ./...
	golangci-lint run --issues-exit-code 0 --output.code-climate.path=stdout | jq .
	go list ./... | xargs -L1 revive -config .revive.toml -set_exit_status

test-ipam:
	$(MAKE) ensure-postgres
	cd ipam && go test ./... -count=1

test-site-manager:
	cd site-manager && CGO_ENABLED=1 go test -race -p 1 ./... -count=1

test-workflow:
	$(MAKE) ensure-postgres
	cd workflow && go test -p 1 ./... -count=1

test-db:
	$(MAKE) ensure-postgres
	cd db && go test -p 1 ./... -count=1

core-mock-server-build:
	mkdir -p build
	cd site-agent/cmd/mock-core && go build -o ../../../build/mock-core .

core-mock-server-start: core-mock-server-build
	-lsof -ti:11079 | xargs kill -9 2>/dev/null
	./build/mock-core -tout 0 > build/mock-core.log 2>&1 & echo $$! > build/mock-core.pid
	@echo "Waiting for gRPC server to start..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		if grep -q "Started API server" build/mock-core.log 2>/dev/null; then \
			sleep 0.1; \
			echo "gRPC server is ready"; \
			exit 0; \
		fi; \
		sleep 0.2; \
	done; \
	echo "Timeout waiting for Mock Core gRPC server to start"; \
	exit 1

core-mock-server-stop:
	-kill $$(cat build/mock-core.pid) 2>/dev/null
	-rm -f build/mock-core.pid

flow-mock-server-build:
	mkdir -p build
	cd site-agent/cmd/mock-flow && go build -o ../../../build/mock-flow .

flow-mock-server-start: flow-mock-server-build
	-lsof -ti:11080 | xargs kill -9 2>/dev/null
	./build/mock-flow -tout 0 > build/mock-flow.log 2>&1 & echo $$! > build/mock-flow.pid
	@echo "Waiting for Flow gRPC server to start..."
	@for i in 1 2 3 4 5 6 7 8 9 10; do \
		if grep -q "Started Flow API server" build/mock-flow.log 2>/dev/null; then \
			sleep 0.1; \
			echo "Flow gRPC server is ready"; \
			exit 0; \
		fi; \
		sleep 0.2; \
	done; \
	echo "Timeout waiting for Mock Flow gRPC server to start"; \
	exit 1

flow-mock-server-stop:
	-kill $$(cat build/mock-flow.pid) 2>/dev/null
	-rm -f build/mock-flow.pid

test-site-agent: core-mock-server-start flow-mock-server-start
	cd site-agent/pkg/components && CGO_ENABLED=1 go test -race -p 1 ./... -count=1 ; \
	ret=$$? ; cd ../../.. && $(MAKE) core-mock-server-stop flow-mock-server-stop ; exit $$ret

test-api:
	$(MAKE) ensure-postgres
	cd api && go test -p 1 ./... -count=1

test-auth:
	$(MAKE) ensure-postgres
	cd auth && go test -p 1 ./... -count=1

test-common:
	cd common && go test -p 1 ./... -count=1

test-cert-manager:
	cd cert-manager && go test -p 1 ./... -count=1

test-site-workflow:
	cd site-workflow && go test -p 1 ./... -count=1

test-flow:
	$(MAKE) ensure-postgres
	cd flow && \
		DB_HOST=localhost \
		DB_PORT=$(POSTGRES_PORT) \
		DB_USER=$(POSTGRES_USER) \
		DB_PASSWORD=$(POSTGRES_PASSWORD) \
		DB_NAME=$(POSTGRES_DB) \
		go test -p 1 ./... -count=1

test: test-ipam test-db test-api test-auth test-common test-cert-manager test-site-workflow test-site-manager test-workflow test-site-agent test-flow

build:
	mkdir -p $(BUILD_DIR)
	go mod download
	cd api && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-extldflags '-static'" -o ../$(BUILD_DIR)/api ./cmd/api
	cd workflow && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-extldflags '-static'" -o ../$(BUILD_DIR)/workflow ./cmd/workflow
	cd site-manager && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-extldflags '-static'" -o ../$(BUILD_DIR)/sitemgr ./cmd/sitemgr
	cd site-agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-extldflags '-static'" -o ../$(BUILD_DIR)/site-agent ./cmd/site-agent
	cd db && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-extldflags '-static'" -o ../$(BUILD_DIR)/migrations ./cmd/migrations
	cd cert-manager && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-extldflags '-static'" -o ../$(BUILD_DIR)/credsmgr ./cmd/credsmgr
	cd cli && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-extldflags '-static'" -o ../$(BUILD_DIR)/nicocli ./cmd/cli

INSTALL_DIR ?= $(shell go env GOPATH)/bin

nico-cli:
	go build -o $(INSTALL_DIR)/nicocli ./cli/cmd/cli
	@echo "Installed nicocli to $(INSTALL_DIR)/nicocli"

docker-build:
	docker build -t $(IMAGE_REGISTRY)/nico-rest-api:$(IMAGE_TAG) -f $(DOCKERFILE_DIR)/Dockerfile.nico-rest-api .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-workflow:$(IMAGE_TAG) -f $(DOCKERFILE_DIR)/Dockerfile.nico-rest-workflow .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-site-manager:$(IMAGE_TAG) -f $(DOCKERFILE_DIR)/Dockerfile.nico-rest-site-manager .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-site-agent:$(IMAGE_TAG) -f $(DOCKERFILE_DIR)/Dockerfile.nico-rest-site-agent .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-db:$(IMAGE_TAG) -f $(DOCKERFILE_DIR)/Dockerfile.nico-rest-db .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-cert-manager:$(IMAGE_TAG) -f $(DOCKERFILE_DIR)/Dockerfile.nico-rest-cert-manager .
	docker build -t $(IMAGE_REGISTRY)/nico-flow:$(IMAGE_TAG) -f $(DOCKERFILE_DIR)/Dockerfile.nico-flow .
	docker build -t $(IMAGE_REGISTRY)/nico-psm:$(IMAGE_TAG) -f $(DOCKERFILE_DIR)/Dockerfile.nico-psm .
	docker build -t $(IMAGE_REGISTRY)/nico-nsm:$(IMAGE_TAG) -f $(DOCKERFILE_DIR)/Dockerfile.nico-nsm .

core-proto: core-proto-fetch core-proto-fmt core-protogen

core-proto-clean:
	@echo "Cleaning up Core proto and protobuf files"
	rm -rf workflow-schema/site-agent/workflows/v1/*_nico.proto
	rm -rf workflow-schema/schema/site-agent/workflows/v1/*.pb.go

core-proto-fetch:
	@for file in ../crates/rpc/proto/*.proto; do \
		cp "$$file" "workflow-schema/site-agent/workflows/v1/$$(basename "$$file" .proto)_nico.proto"; \
		echo "Copied: $$file"; \
	done
	mv workflow-schema/site-agent/workflows/v1/forge_nico.proto workflow-schema/site-agent/workflows/v1/nico_nico.proto
	echo "Successfully copied Core protobuf files"

core-proto-fmt:
	@echo "Formatting Core protobuf files"
	cd workflow-schema/cmd/core-proto-fmt && go run main.go

core-protogen:
	echo "Generating protobuf for Core"
	cd workflow-schema && buf generate
	go fmt ./...

flow-proto:
	FLOW_DIR=flow; \
	ls "$${FLOW_DIR}/proto/v1"; \
	for file in "$${FLOW_DIR}"/proto/v1/*.proto; do \
		cp "$$file" "workflow-schema/flow/proto/v1/"; \
		echo "Copied: $$file"; \
		./workflow-schema/scripts/add-go-package-option.sh "workflow-schema/flow/proto/v1/$$(basename "$$file")" "github.com/NVIDIA/infra-controller/rest-api/workflow-schema/flow"; \
	done

flow-protogen:
	echo "Generating protobuf for Flow"
	cd workflow-schema/flow && buf generate
	go fmt ./...

# =============================================================================
# Kind Local Deployment Targets
# =============================================================================

.PHONY: kind-up kind-down kind-deploy kind-load kind-apply kind-redeploy kind-status kind-logs kind-reset kind-reset-infra kind-reset-kustomize kind-reset-helm kind-verify setup-site-agent test-simple-sdk-example
.PHONY: deploy-overlay-api deploy-overlay-cert-manager deploy-overlay-site-manager deploy-overlay-workflow
.PHONY: helm-lint helm-template helm-deploy helm-deploy-site-agent helm-deploy-all helm-redeploy helm-verify helm-verify-site-agent helm-uninstall

# Kind cluster configuration
KIND_CLUSTER_NAME := nico-rest-local
KUSTOMIZE_OVERLAY := deploy/kustomize/overlays/local
LOCAL_DOCKERFILE_DIR := docker/local

# Recommended colima configuration for full stack with Temporal:
#   colima start --cpu 8 --memory 8 --disk 100

# Build images using local Dockerfiles (public base images for local dev)
docker-build-local:
	docker build -t $(IMAGE_REGISTRY)/nico-rest-api:$(IMAGE_TAG) -f $(LOCAL_DOCKERFILE_DIR)/Dockerfile.nico-rest-api .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-workflow:$(IMAGE_TAG) -f $(LOCAL_DOCKERFILE_DIR)/Dockerfile.nico-rest-workflow .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-site-manager:$(IMAGE_TAG) -f $(LOCAL_DOCKERFILE_DIR)/Dockerfile.nico-rest-site-manager .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-site-agent:$(IMAGE_TAG) -f $(LOCAL_DOCKERFILE_DIR)/Dockerfile.nico-rest-site-agent .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-mock-core:$(IMAGE_TAG) -f $(LOCAL_DOCKERFILE_DIR)/Dockerfile.nico-rest-mock-core .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-db:$(IMAGE_TAG) -f $(LOCAL_DOCKERFILE_DIR)/Dockerfile.nico-rest-db .
	docker build -t $(IMAGE_REGISTRY)/nico-rest-cert-manager:$(IMAGE_TAG) -f $(LOCAL_DOCKERFILE_DIR)/Dockerfile.nico-rest-cert-manager .

# Create kind cluster with port mappings
kind-up:
	kind create cluster --name $(KIND_CLUSTER_NAME) --config deploy/kind/cluster-config.yaml
	#kubectl apply -f deploy/kustomize/base/crds/

# Delete kind cluster
kind-down:
	kind delete cluster --name $(KIND_CLUSTER_NAME)

# Full deployment: build images, load into kind, apply manifests
kind-deploy: docker-build-local kind-load kind-apply
	@echo "Deployment complete. Run 'make kind-verify' to verify."

# Load all images into kind cluster
kind-load:
	kind load docker-image $(IMAGE_REGISTRY)/nico-rest-api:$(IMAGE_TAG) --name $(KIND_CLUSTER_NAME)
	kind load docker-image $(IMAGE_REGISTRY)/nico-rest-workflow:$(IMAGE_TAG) --name $(KIND_CLUSTER_NAME)
	kind load docker-image $(IMAGE_REGISTRY)/nico-rest-site-manager:$(IMAGE_TAG) --name $(KIND_CLUSTER_NAME)
	kind load docker-image $(IMAGE_REGISTRY)/nico-rest-site-agent:$(IMAGE_TAG) --name $(KIND_CLUSTER_NAME)
	kind load docker-image $(IMAGE_REGISTRY)/nico-rest-mock-core:$(IMAGE_TAG) --name $(KIND_CLUSTER_NAME)
	kind load docker-image $(IMAGE_REGISTRY)/nico-rest-db:$(IMAGE_TAG) --name $(KIND_CLUSTER_NAME)
	kind load docker-image $(IMAGE_REGISTRY)/nico-rest-cert-manager:$(IMAGE_TAG) --name $(KIND_CLUSTER_NAME)

# Apply kustomize manifests and wait for readiness
kind-apply:
	kubectl apply -k $(KUSTOMIZE_OVERLAY)
	@echo "Waiting for PostgreSQL..."
	kubectl -n postgres rollout status statefulset/postgres --timeout=120s
	@echo "Waiting for Cert Manager..."
	kubectl -n nico-rest rollout status deployment/nico-rest-cert-manager --timeout=180s
	@echo "Waiting for Temporal..."
	kubectl -n temporal rollout status deployment/temporal-frontend --timeout=120s || true
	@echo "Waiting for Keycloak..."
	kubectl -n nico-rest rollout status deployment/keycloak --timeout=180s
	@echo "Running database migrations..."
	kubectl -n nico-rest wait --for=condition=complete job/nico-rest-db-migration --timeout=120s
	@echo "Waiting for API service..."
	kubectl -n nico-rest rollout status deployment/nico-rest-api --timeout=120s || true
	@echo "Waiting for Site Manager..."
	kubectl -n nico-rest rollout restart deployment/nico-rest-site-manager || true
	kubectl -n nico-rest rollout status deployment/nico-rest-site-manager --timeout=120s || true
	@echo "Waiting for Site Agent..."
	kubectl -n nico-rest rollout restart statefulset/nico-rest-site-agent || true
	kubectl -n nico-rest rollout status statefulset/nico-rest-site-agent --timeout=120s || true

# Rebuild and redeploy apps only (faster iteration, preserves DB/certs/secrets)
kind-redeploy: docker-build-local kind-load
	kubectl -n nico-rest rollout restart deployment/nico-rest-api
	kubectl -n nico-rest rollout restart deployment/nico-rest-cloud-worker
	kubectl -n nico-rest rollout restart deployment/nico-rest-site-worker
	kubectl -n nico-rest rollout restart deployment/nico-rest-mock-core
	kubectl -n nico-rest rollout restart deployment/nico-rest-cert-manager
	kubectl -n nico-rest rollout restart deployment/nico-rest-site-manager
	kubectl -n nico-rest rollout restart statefulset/nico-rest-site-agent
	@echo "Waiting for rollouts..."
	kubectl -n nico-rest rollout status deployment/nico-rest-api --timeout=120s
	kubectl -n nico-rest rollout status deployment/nico-rest-cloud-worker --timeout=120s
	kubectl -n nico-rest rollout status deployment/nico-rest-site-worker --timeout=120s
	kubectl -n nico-rest rollout status deployment/nico-rest-mock-core --timeout=120s
	kubectl -n nico-rest rollout status deployment/nico-rest-cert-manager --timeout=120s
	kubectl -n nico-rest rollout status deployment/nico-rest-site-manager --timeout=120s
	kubectl -n nico-rest rollout status statefulset/nico-rest-site-agent --timeout=120s
	@echo ""
	@echo "Redeploy complete. All pods ready."
	@kubectl -n nico-rest get pods

# Show status of all pods and services
kind-status:
	kubectl -n nico-rest get pods,svc,jobs

# View logs from API service
kind-logs:
	kubectl -n nico-rest logs -l app=nico-rest-api -f --tail=100

# Scoped overlays: deploy only one component + its deps (no duplication of yaml; requires LoadRestrictionsNone)
deploy-overlay-api:
	kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/kustomize/overlays/api | kubectl apply -f -
deploy-overlay-cert-manager:
	kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/kustomize/overlays/cert-manager | kubectl apply -f -
deploy-overlay-site-manager:
	kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/kustomize/overlays/site-manager | kubectl apply -f -
deploy-overlay-workflow:
	kubectl kustomize --load-restrictor LoadRestrictionsNone deploy/kustomize/overlays/workflow | kubectl apply -f -

# =============================================================================
# Kind: Shared Infrastructure (used by both Helm and Kustomize deployment paths)
# =============================================================================

# Shared infrastructure: cluster, cert-manager.io, PostgreSQL, Temporal, Keycloak,
# and mock-core (dev only).
# common secrets and credsmgr are now installed as part of the Helm chart (nico-rest-common,
# nico-rest-cert-manager sub-charts). App services are deployed separately by
# kind-reset-helm or kind-reset-kustomize.
kind-reset-infra: docker-build-local
	-kind delete cluster --name $(KIND_CLUSTER_NAME)
	kind create cluster --name $(KIND_CLUSTER_NAME) --config deploy/kind/cluster-config.yaml
	$(MAKE) kind-load

	@echo "Installing cert-manager.io..."
	kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.14.4/cert-manager.yaml
	@echo "Waiting for cert-manager deployments..."
	kubectl -n cert-manager rollout status deployment/cert-manager --timeout=240s
	kubectl -n cert-manager rollout status deployment/cert-manager-webhook --timeout=240s
	kubectl -n cert-manager rollout status deployment/cert-manager-cainjector --timeout=240s

	@echo "Creating nico-rest namespace..."
	kubectl create namespace nico-rest || true

	@echo "Setting up PKI secrets for cert-manager..."
	NAMESPACE=nico-rest ./scripts/setup-local.sh pki

	@echo "Setting up PostgreSQL..."
	kubectl apply -k deploy/kustomize/base/postgres/
	kubectl -n postgres rollout status statefulset/postgres --timeout=240s

	@echo "Configuring cert-manager.io ClusterIssuer..."
	kubectl apply -k deploy/kustomize/base/cert-manager-io/

	@echo "Creating temporal namespace..."
	kubectl create namespace temporal || true
	@echo "Creating Temporal certificates and database credentials..."
	kubectl apply -k deploy/kustomize/base/temporal-helm/
	@echo "Waiting for Temporal certificates to be issued..."
	kubectl -n temporal wait --for=condition=Ready certificate/server-interservice-cert --timeout=240s || true
	kubectl -n temporal wait --for=condition=Ready certificate/server-cloud-cert --timeout=240s || true
	kubectl -n temporal wait --for=condition=Ready certificate/server-site-cert --timeout=240s || true
	@echo "Updating Helm chart dependencies..."
	helm dependency update temporal-helm/temporal/
	@echo "Installing Temporal via Helm chart..."
	helm upgrade --install temporal ./temporal-helm/temporal \
		--namespace temporal \
		--values ./temporal-helm/temporal/values-kind.yaml \
		--wait --timeout 16m || true
	@echo "Waiting for Temporal services..."
	kubectl -n temporal rollout status deployment/temporal-frontend --timeout=360s || true
	kubectl -n temporal rollout status deployment/temporal-history --timeout=360s || true
	kubectl -n temporal rollout status deployment/temporal-matching --timeout=360s || true
	kubectl -n temporal rollout status deployment/temporal-worker --timeout=360s || true
	@echo "Creating Temporal namespaces with TLS..."
	kubectl -n temporal exec deploy/temporal-admintools -- temporal operator namespace create --namespace cloud --address temporal-frontend.temporal:7233 \
		--tls-cert-path /var/secrets/temporal/certs/server-interservice/tls.crt \
		--tls-key-path /var/secrets/temporal/certs/server-interservice/tls.key \
		--tls-ca-path /var/secrets/temporal/certs/server-interservice/ca.crt \
		--tls-server-name interservice.server.temporal.local || true
	kubectl -n temporal exec deploy/temporal-admintools -- temporal operator namespace create --namespace site --address temporal-frontend.temporal:7233 \
		--tls-cert-path /var/secrets/temporal/certs/server-interservice/tls.crt \
		--tls-key-path /var/secrets/temporal/certs/server-interservice/tls.key \
		--tls-ca-path /var/secrets/temporal/certs/server-interservice/ca.crt \
		--tls-server-name interservice.server.temporal.local || true
	@echo "Temporal Helm deployment ready"

	@echo "Setting up Keycloak..."
	kubectl apply -k deploy/kustomize/base/keycloak
	kubectl -n nico-rest rollout status deployment/keycloak --timeout=240s

	@echo "Setting up Nico Mock Core (dev only, not in Helm chart)..."
	kubectl apply -k deploy/kustomize/overlays/mock-core
	kubectl -n nico-rest rollout status deployment/nico-rest-mock-core --timeout=240s

	@echo ""
	@echo "================================================================================"
	@echo "Infrastructure ready! Now deploy app services with:"
	@echo "  make helm-deploy              # Helm umbrella chart"
	@echo "  make helm-deploy-site-agent   # Helm site-agent chart"
	@echo "  — or —"
	@echo "  make kind-reset-kustomize     # Full reset + Kustomize app deployment"
	@echo "================================================================================"

# =============================================================================
# Kind: Kustomize Deployment (alternative to Helm)
# =============================================================================

# Full reset with Kustomize-based app deployment
kind-reset-kustomize: kind-reset-infra
	@echo "Deploying app services via Kustomize overlays..."

	@echo "Setting up common secrets..."
	kubectl apply -k deploy/kustomize/base/common
	kubectl -n nico-rest wait --for=condition=Ready certificate/temporal-client-cloud-cert --timeout=240s || true

	@echo "Setting up Nico REST Cert Manager (credsmgr)..."
	kubectl apply -k deploy/kustomize/overlays/cert-manager
	kubectl -n nico-rest rollout status deployment/nico-rest-cert-manager --timeout=240s

	@echo "Waiting for Nico REST Site Manager..."
	kubectl apply -k deploy/kustomize/overlays/site-manager
	kubectl -n nico-rest rollout status deployment/nico-rest-site-manager --timeout=240s

	@echo "Setting up Nico REST DB Migration..."
	kubectl apply -k deploy/kustomize/overlays/db
	kubectl -n nico-rest wait --for=condition=complete job -l app=nico-rest-db-migration --timeout=240s

	@echo "Setting up Nico REST Cloud and Site Workers..."
	kubectl apply -k deploy/kustomize/overlays/workflow
	kubectl -n nico-rest rollout status deployment/nico-rest-cloud-worker --timeout=240s
	kubectl -n nico-rest rollout status deployment/nico-rest-site-worker --timeout=240s

	@echo "Setting up Nico REST API..."
	kubectl apply -k deploy/kustomize/overlays/api
	kubectl -n nico-rest rollout status deployment/nico-rest-api --timeout=240s

	@echo "Setting up Nico REST Site Agent..."
	kubectl apply -k deploy/kustomize/overlays/site-agent
	kubectl -n nico-rest rollout status statefulset/nico-rest-site-agent --timeout=240s

	@echo "Setting up Site Agent secrets..."
	./scripts/setup-local.sh site-agent

	@echo ""
	@echo "================================================================================"
	@echo "Deployment complete! (Kustomize)"
	@echo ""
	@echo "Temporal UI: http://localhost:8233"
	@echo "API: http://localhost:8388"
	@echo "Keycloak: http://localhost:8082"
	@echo "================================================================================"

# =============================================================================
# Kind: Helm Deployment (default)
# =============================================================================

# Full reset with Helm-based app deployment (default for kind-reset)
kind-reset-helm: kind-reset-infra
	@echo "Deploying app services via Helm charts..."
	$(MAKE) helm-deploy
	$(MAKE) helm-deploy-site-agent
	@echo ""
	@echo "================================================================================"
	@echo "Deployment complete! (Helm)"
	@echo ""
	@echo "Temporal UI: http://localhost:8233"
	@echo "API: http://localhost:8388"
	@echo "Keycloak: http://localhost:8082"
	@echo "================================================================================"

# Default: full reset using Helm deployment
kind-reset: kind-reset-helm

# =============================================================================
# Helm Charts
# =============================================================================

helm-lint:
	helm lint $(UMBRELLA_CHART)/ $(HELM_SET) $(HELM_SET_KEYCLOAK)
	helm lint $(SITE_AGENT_CHART)/ $(HELM_SET)

helm-template:
	@echo "--- nico-rest (umbrella) ---"
	helm template nico-rest $(UMBRELLA_CHART)/ $(HELM_SET) $(HELM_SET_KEYCLOAK) --namespace nico-rest
	@echo "--- nico-rest-site-agent ---"
	helm template nico-rest-site-agent $(SITE_AGENT_CHART)/ $(HELM_SET) --namespace nico-rest

# Deploy umbrella chart (api + workflow + site-manager + db)
# Note: images must be loaded into kind before calling this (kind-load or kind-reset-infra)
helm-deploy:
	helm upgrade --install nico-rest $(UMBRELLA_CHART)/ \
		--namespace nico-rest --create-namespace $(HELM_SET) $(HELM_SET_KEYCLOAK) \
		--set nico-rest-api.nodePort.enabled=true \
		--set nico-rest-api.nodePort.port=30388 \
		--wait --timeout 5m
	@echo ""
	@echo "================================================================================"
	@echo "Umbrella chart deployed. To deploy site-agent:"
	@echo "  make helm-deploy-site-agent"
	@echo "================================================================================"

# Deploy site-agent: install chart first (will CrashLoop), then bootstrap, then stabilize
helm-deploy-site-agent:
	@echo "Installing site-agent chart (will CrashLoop until bootstrapped)..."
	helm upgrade --install nico-rest-site-agent $(SITE_AGENT_CHART)/ \
		--namespace nico-rest $(HELM_SET) --timeout 1m || true
	@echo "Running site bootstrap (setup-local.sh site-agent)..."
	./scripts/setup-local.sh site-agent
	@echo "Waiting for site-agent to stabilize..."
	kubectl -n nico-rest rollout status statefulset/nico-rest-site-agent --timeout=120s

# Deploy everything (umbrella + site-agent)
helm-deploy-all: helm-deploy helm-deploy-site-agent

# Rebuild images and redeploy umbrella chart via Helm (excludes site-agent; use helm-deploy-site-agent separately)
helm-redeploy: docker-build-local kind-load helm-deploy

helm-verify:
	@echo "Checking Site Manager..."
	kubectl -n nico-rest rollout status deployment/nico-rest-site-manager --timeout=120s
	@echo "Checking Cloud Worker..."
	kubectl -n nico-rest rollout status deployment/nico-rest-cloud-worker --timeout=120s
	@echo "Checking Site Worker..."
	kubectl -n nico-rest rollout status deployment/nico-rest-site-worker --timeout=120s
	@echo "Checking API..."
	kubectl -n nico-rest rollout status deployment/nico-rest-api --timeout=120s
	@echo ""
	@echo "All umbrella chart services are ready."
	@kubectl -n nico-rest get pods

helm-verify-site-agent:
	@echo "Checking Site Agent..."
	kubectl -n nico-rest rollout status statefulset/nico-rest-site-agent --timeout=120s

helm-uninstall:
	-helm uninstall nico-rest-site-agent --namespace nico-rest
	-helm uninstall nico-rest --namespace nico-rest

# =============================================================================
# Kind: Utilities
# =============================================================================

# Setup site-agent with a real site created via the API
setup-site-agent:
	./scripts/setup-local.sh site-agent

# Verify the local deployment (health checks)
kind-verify:
	./scripts/setup-local.sh verify

# Run the simple SDK Machine example against local dev (kind).
# Verifies the SDK can talk to the stack (list, get machines).
# Requires: kind cluster running, port-forward API (8388) and Keycloak (8082). Uses NICO_* env vars or defaults.
test-simple-sdk-example:
	@command -v jq >/dev/null 2>&1 || { echo "jq is required (e.g. brew install jq)"; exit 1; }
	@echo "Running simple SDK Machine example against local dev..."
	NICO_BASE_URL=$${NICO_BASE_URL:-http://localhost:8388} \
	NICO_ORG=$${NICO_ORG:-test-org} \
	NICO_TOKEN=$${NICO_TOKEN:-$$(curl -s -X POST "http://localhost:8082/realms/nico-dev/protocol/openid-connect/token" \
		-H "Content-Type: application/x-www-form-urlencoded" \
		-d "client_id=nico-api" \
		-d "client_secret=nico-local-secret" \
		-d "grant_type=password" \
		-d "username=admin@example.com" \
		-d "password=adminpassword" | jq -r .access_token)} \
	go run ./sdk/simple/examples/machine/

# Run PKI E2E tests
test-pki:
	./scripts/test-pki.sh

# Run Temporal mTLS and rotation tests
test-temporal-e2e:
	./scripts/test-temporal.sh all

# =============================================================================
# Generated Go API Client
# =============================================================================

# OpenAPI spec path or URL for SDK generation. Override with: OPENAPI_SPEC=/path/to/spec.yaml make generate-sdk
OPENAPI_SPEC ?= openapi/spec.yaml

# Generate Go API SDK from OpenAPI spec using openapi-generator
# Requires: brew install openapi-generator
generate-sdk:
	openapi-generator generate \
		-i $(OPENAPI_SPEC) \
		-g go \
		-o sdk/standard \
		--package-name standard \
		--additional-properties=isGoSubmodule=true,enumClassPrefix=true \
		--global-property=apis,models,supportingFiles
	rm -rf sdk/standard/docs sdk/standard/api sdk/standard/README.md sdk/standard/test sdk/standard/.openapi-generator
	python3 scripts/check_source_headers.py --fix
	@echo "Client generated in sdk/standard/"
	cd sdk/standard && go build ./...
	@echo "Client compiles successfully"
	cd sdk/standard && go fmt ./...

# =============================================================================
# OpenAPI Spec Validation
# =============================================================================

# Validate OpenAPI spec using Redocly CLI (Docker)
lint-openapi:
	npx @redocly/cli lint --skip-rule=no-ambiguous-paths ./openapi/spec.yaml

# Preview OpenAPI spec in Redoc UI (Docker)
preview-openapi:
	@echo "Starting Redoc UI at http://127.0.0.1:8090"
	docker run -it --rm -p 8090:80 -v ./openapi/spec.yaml:/usr/share/nginx/html/openapi.yaml -e SPEC_URL=openapi.yaml -e REDOC_OPTIONS="expand-responses=200,201 schemas-expansion-level=2" redocly/redoc:v2.5.1

publish-openapi:
	npx @redocly/cli build-docs --config=./openapi/redocly.yaml ./openapi/spec.yaml -o ./docs/index.html

# =============================================================================
# Pre-commit Hooks (TruffleHog Secret Detection)
# =============================================================================

# Install pre-commit hooks
pre-commit-install:
	@command -v pre-commit >/dev/null 2>&1 || { echo "Installing pre-commit..."; pip install pre-commit; }
	@command -v trufflehog >/dev/null 2>&1 || { echo "Installing trufflehog..."; brew install trufflehog || go install github.com/trufflesecurity/trufflehog/v3@latest; }
	pre-commit install
	pre-commit install --hook-type pre-push
	@echo "Pre-commit hooks installed successfully!"

# Run pre-commit on all files
pre-commit-run:
	pre-commit run --all-files

# Update pre-commit hooks to latest versions
pre-commit-update:
	pre-commit autoupdate
