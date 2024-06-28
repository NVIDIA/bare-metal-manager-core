#set shell := ["bash", "-uc"]
export DOCKER_BUILDKIT := "1"

components_dir := "api pxe dns dhcp dev/bmc-mock admin"
components_name := "\"carbide-api --features carbide-api/tss-esapi\" carbide-pxe carbide-dns dhcp bmc-mock admin"

# Start cargo-watch for components "{{components}}"
watch: check forged-link skaffold-dirs
  parallel --link  -j+0 --tty --tag cargo --color=always watch --why -C {1} -s \"${REPO_ROOT}/.skaffold/build {2}\" ::: {{components_dir}} ::: {{components_name}}

# Build components one time
build: check forged-link skaffold-dirs
  parallel --link  -j+0 --tty --tag "${REPO_ROOT}"/.skaffold/build {1} ::: {{components_name}}

_dockerbuild NAME FILE CONTEXT=(invocation_directory()):
  DOCKER_BUILDKIT=1 docker build -t {{NAME}} -f {{FILE}} {{CONTEXT}}

# Build the carbide build-container used for compiling
build-container: (_dockerbuild "urm.nvidia.com/swngc-ngcc-docker-local/forge/carbide/x86-64/build-container:latest" "dev/docker/Dockerfile.build-container-x86_64" "dev/docker")

# Build the build-container used for minikube forge development
build-container-minikube: build-container (_dockerbuild "registry.minikube/build-container:latest" "dev/deployment/localdev/Dockerfile.build-container.localdev" "dev/deployment")
build-container-k3s: build-container (_dockerbuild "build-container-localdev:latest" "dev/deployment/localdev/Dockerfile.build-container.localdev" "dev/deployment")

# Build the runtime-container for minikube development. This gets used for deploying forge containers
runtime-container-minikube: (_dockerbuild "registry.minikube/runtime-container:latest" "dev/deployment/localdev/Dockerfile.runtime-container.localdev")
runtime-container-k3s: (_dockerbuild "runtime-container-localdev:latest" "dev/deployment/localdev/Dockerfile.runtime-container.localdev")

load-minikube-registry: runtime-container-minikube build-container-minikube
  minikube image load registry.minikube/build-container:latest
  minikube image load registry.minikube/runtime-container:latest

check-binaries-in-path:
  @which parallel 2>&1 &>/dev/null || (echo "parallel not found" && exit 1)
  @which skaffold 2>&1 &>/dev/null || (echo "skaffold not found" && exit 1)
  @echo "checked binaries, OK"

check-envs:
  @TMP_UNUSED_VAR=$FORGED_DIRECTORY
  @echo "checked environment variables, OK"

check:
  @just -f {{justfile()}} check-binaries-in-path
  @just -f {{justfile()}} check-envs

forged-link: check-envs
  #!/usr/bin/env bash
  set -euo pipefail
  test -e ./forged || ln -s $FORGED_DIRECTORY ./forged || (echo "Could not link FORGED_DIRECTORY $FORGED_DIRECTORY to ./forged, does it exist?" && exit 1)

skaffold-dirs:
  #!/usr/bin/env bash
  set -euo pipefail
  test -d .skaffold/cache || mkdir -p .skaffold/cache
  test -d .skaffold/target || mkdir -p .skaffold/target

test_docker_containers:
  #!/usr/bin/env bash
  echo "Initiating docker postgres container for testing named: pgdev"
  docker kill pgdev 2>/dev/null
  docker run --rm -di -e POSTGRES_PASSWORD="admin" --net=host --name pgdev postgres:14.5-alpine

clean_postgres:
  #!/usr/bin/env bash
  echo "Cleaning forge postgres DB"
  ./dev/bin/nuke-postgres.sh
