
KUSTOMIZE_VERSION ?= v3.8.7
CONTROLLER_TOOLS_VERSION ?= v0.9.0
GOLANG_VERSION ?= 1.18
ENVTEST_K8S_VERSION = 1.24.1
HELMIFY_VERSION = v0.3.7

# Image URL to use all building/pushing image targets
IMG ?= quay.io/nvidia/forge-connectivity:latest
OVN_IMG ?= quay.io/nvidia/forge-connectivity-ovn:v21.06
TEST_IMG ?= forge-connectivity/test:latest
BUILD_IMAGE ?= golang:$(GOLANG_VERSION)
KUSTOMIZE_IMAGE ?= k8s.gcr.io/kustomize/kustomize:$(KUSTOMIZE_VERSION)
# Tool Chain images not pushed to quay
PROTOC_IMAGE ?= forge/protoc:3.12.4
CONTROLLER_GEN_IMAGE ?= forge/controller-gen:$(CONTROLLER_TOOLS_VERSION)

BUILD_DIRS := bin       \
			.go/cache 	\
			.go/pkg 

GOOS ?= linux
GOARCH ?= amd64
VERSION ?= $(shell git describe --tags --always --dirty)
TAG := $(VERSION)__$(OS)_$(ARCH)


DBUILD=CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH)
BUILD_OPTS=
DOCKERIZED ?= true

# SRC_DIR is used to to help with DOCKERIZED mode, in standard mode
# this is just CURDIR, but we use a different dir name in build container
# so we distinguish here, and modify if DOCKERIZED=true
SRC_DIR=$(CURDIR)

# Produce CRDs that work back to Kubernetes 1.11 (no version conversion)
# CRD_OPTIONS ?= "crd:trivialVersions=true,preserveUnknownFields=false"
CRD_OPTIONS =
PROTO_C ?= protoc

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif
IN_CI=$(shell printenv IN_CI)

TEST_IMG_EXISTS=$(shell docker images ${TEST_IMG} -q)

# Setting SHELL to bash allows bash commands to be executed by recipes.
# This is a requirement for 'setup-envtest.sh' in the test target.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

all: build


ifeq (${IN_CI},true)
DOCKERIZE=
DOCKERIZED=false
else
DOCKERIZE=docker run --rm --privileged -t -i \
          		-e "GOCACHE=/tmp/gocache" \
          		-e "GOPATH=/tmp/gopath" \
          		-e ENVTEST_K8S_VERSION=$(ENVTEST_K8S_VERSION) \
          		-w /usr/src/forge \
          		-v $(shell go env GOPATH):/tmp/gopath:ro \
          		-v $(shell go env GOCACHE):/tmp/gocache:ro \
          		-v $(CURDIR):/usr/src/forge \
          		${TEST_IMG}

endif

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
KUSTOMIZE = $(shell pwd)/bin/kustomize
ENVTEST = $(shell pwd)/bin/setup-envtest
HELMIFY = $(shell pwd)/bin/helmify

ifeq ($(DOCKERIZED),true)
$(info running with DOCKERIZED set to true...)
KUSTOMIZE=docker run 										\
						-i 													\
						--rm 												\
						-u $$(id -u):$$(id -g) 			\
						-v $(CURDIR)/config:/config \
						-w /                        \
						--entrypoint /app/kustomize \
						$(KUSTOMIZE_IMAGE) 					


DBUILD=docker run 											\
		    -i 															\
		    --rm 														\
		    -u $$(id -u):$$(id -g) 					\
		    -v $(CURDIR):/src 							\
		    -w /src 												\
		    -v $(CURDIR)/.go/cache:/.cache 	\
		    -v $(CURDIR)/.go/pkg:/go/pkg 		\
        -e GOOS=$(GOOS)                 \
        -e GOARCH=$(GOARCH)             \
        -e CGO_ENABLED=$(CGO_ENABLED)   \
		    $(BUILD_IMAGE) 									

CONTROLLER_GEN=docker run 							\
		    -i 															\
		    --rm 														\
		    -u $$(id -u):$$(id -g) 					\
		    -v $(CURDIR):/src 							\
		    -w /src 												\
		    -v $(CURDIR)/.go/cache:/.cache 	\
		    -v $(CURDIR)/.go/pkg:/go/pkg 		\
				$(CONTROLLER_GEN_IMAGE) 				

PROTO_C=docker run 											\
		    -i 															\
		    --rm 														\
		    -u $$(id -u):$$(id -g) 					\
		    -v $(CURDIR):/src 							\
		    -w /src 												\
		    -v $(CURDIR)/.go/cache:/.cache 	\
		    -v $(CURDIR)/.go/pkg:/go/pkg 		\
				$(PROTOC_IMAGE) 								
endif

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

manifests: controller-gen kustomize ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=manager-role webhook crd paths="./apis/..."  output:crd:artifacts:config=config/crd/bases
	FORGE_CONTROL_PLANE=forge envsubst < config/default/kustomization.template.yaml > config/default/kustomization.yaml
	$(KUSTOMIZE) build config/default > config/forge.yaml
	FORGE_CONTROL_PLANE=forge-canary envsubst < config/default/kustomization.template.yaml > config/default/kustomization.yaml
	$(KUSTOMIZE) build config/default > config/forge-canary.yaml
	FORGE_CONTROL_PLANE=forge-dev envsubst < config/default/kustomization.template.yaml > config/default/kustomization.yaml
	$(KUSTOMIZE) build config/default > config/forge-dev.yaml
	rm config/default/kustomization.yaml

manifests-ci: manifests helmify
	FORGE_CONTROL_PLANE=forge envsubst < config/default/kustomization.template.yaml > config/default/kustomization.yaml
	rm config/default/kustomization.template.yaml
	$(KUSTOMIZE) build config/default | $(HELMIFY) vpc

generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./apis/..."
	$(PROTO_C) --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative rpc/rpc.proto

fmt: ## Run go fmt against code.
	$(info running with DBUILD set to: $(DBUILD))
	$(DBUILD) go fmt ./...

vet: ## Run go vet against code.
	$(DBUILD) go vet ./...

#test: manifests generate fmt vet ## Run tests.
test: mock-gen envtest
	if [[ -z "${TEST_IMG_EXISTS}" ]] && [[ -z "${IN_CI}" ]]; then \
	  docker build -t ${TEST_IMG} -f build/images/forge/Dockerfile.test .;\
	fi
	touch cover.out
	ENVTEST_K8S_VERSION=$(ENVTEST_K8S_VERSION) ${DOCKERIZE} ./hack/run_test.sh

test-env: envtest
	ENVTEST_K8S_VERSION=$(ENVTEST_K8S_VERSION) ${DOCKERIZE}  bash


mock-gen: generate
	./hack/mock_gen.sh

build: generate fmt vet ## Build manager binary.
	$(info running with DBUILD set to: $(DBUILD) $(BUILD_OPTS))
	$(DBUILD) $(BUILD_OPTS) go build -o bin/manager cmd/controller/main.go
	$(DBUILD) $(BUILD_OPTS) go build -o bin/grpc-server cmd/rpc/main.go
	$(DBUILD) $(BUILD_OPTS) go build -o bin/agent cmd/agent/main.go

docker-build: ## Build docker image with the manager.
	docker build -t ${OVN_IMG} -f build/images/ovn/Dockerfile .
	docker build -t ${IMG} -f build/images/forge/Dockerfile .
	docker build -t ${CONTROLLER_GEN_IMAGE} -f build/images/util/controller-gen.Dockerfile .
	docker build -t ${PROTOC_IMAGE} -f build/images/util/protoc.Dockerfile .

docker-push: ## Push docker image with the manager.
	docker push ${IMG}
	docker push ${OVN_IMG}

##@ Deployment

install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.4/cert-manager.yaml
	kubectl apply -f config/forge.yaml

undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config.
	kubectl delete -f config/forge.yaml

# tools
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
controller-gen: ## Download controller-gen locally if necessary.
ifneq ($(DOCKERIZED),true)
	GOBIN=$(PROJECT_DIR)/bin go install sigs.k8s.io/controller-tools/cmd/controller-gen@${CONTROLLER_TOOLS_VERSION}
endif

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
kustomize: ## Download kustomize locally if necessary.
ifneq ($(DOCKERIZED),true)
	test -f $(PROJECT_DIR)/bin/kustomize || curl -s $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(PROJECT_DIR)/bin
endif

envtest: ## Download envtest-setup locally if necessary.
	GOBIN=$(PROJECT_DIR)/bin go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

helmify:
	GOBIN=$(PROJECT_DIR)/bin go install github.com/arttor/helmify/cmd/helmify@${HELMIFY_VERSION}
