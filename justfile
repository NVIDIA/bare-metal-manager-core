#set shell := ["bash", "-uc"]
export DOCKER_BUILDKIT := "1" 

components_dir := "api pxe dns dhcp"
components_name := "carbide-api carbide-pxe carbide-dns dhcp scout"

# Start cargo-watch for components "{{components}}"
watch:
  mkdir -p .skaffold/cache && mkdir -p .skaffold/target && parallel --link  -j+0 --tty --tag cargo --color=always watch --why -C {1} -s \"${REPO_ROOT}/.skaffold/build {2}\" ::: {{components_dir}} ::: {{components_name}}

_dockerbuild NAME FILE CONTEXT=(invocation_directory()):
  DOCKER_BUILDKIT=1 docker build -t {{NAME}} -f {{FILE}} {{CONTEXT}}

# Build the carbide build-container used for compiling
build-container: (_dockerbuild "urm.nvidia.com/swngc-ngcc-docker-local/forge/carbide/x86-64/build-container:v0.0.1-470-g80a16ba9" "dev/docker/Dockerfile.build-container" "dev/docker")

# Build the build-container used for minikube forge development
build-container-minikube: build-container (_dockerbuild "registry.minikube/build-container:latest" "dev/deployment/localdev/Dockerfile.build-container.localdev" "dev/deployment")

# Build the runtime-container for minikube development. This gets used for deploying forge containers
runtime-container-minikube: (_dockerbuild "registry.minikube/runtime-container:latest" "dev/deployment/localdev/Dockerfile.runtime-container.localdev")
