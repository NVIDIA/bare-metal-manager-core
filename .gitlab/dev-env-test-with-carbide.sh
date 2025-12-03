#!/usr/bin/env bash

#
# Used in pipeline job 'dev-env-test-with-carbide'. Designed to run directly on a GitLab runner machine.
#
# This script sets up a single Forge kubernetes deployment (from the 'forged' repo), builds the
# carbide images, and deploys those to the node.
# It then checks that the expected carbide pods were created, and that all kubernetes resources are healthy.
#
# NOTE: Any changes made to this script must (likely) also be made to the script of the same name in the forged repo
#

set -euo pipefail
echo "Current working directory is: $(pwd)"

# Log file paths
PXE_BUILD_X86_LOG="/tmp/pxe-build-x86.log"
PXE_BUILD_AARCH_LOG="/tmp/pxe-build-aarch.log"
CONTAINER_BUILD_LOG="/tmp/container-build.log"

# Merge trunk into branch to improve test reliability
if [[ "$CI_COMMIT_REF_NAME" != "trunk" ]]; then
  echo "Merging 'trunk' into current branch to ensure it's up-to-date..."
  git config user.email "dummy@example.com" && git config user.name "Pre-Merge Test User"
  git fetch origin trunk
  if ! git merge origin/trunk; then
    echo "WARNING: Merge conflict detected with trunk."
    git merge --abort
  fi
else
  echo "Already on 'trunk' (i.e. this is not a pre-merge job), so skipping branch update..."
fi

# Configure PATH and other environment variables
source /root/.bashrc
doas chown -R $USER $CARGO_HOME $RUSTUP_HOME

echo "Generating .local_envrc file..."
echo "export FORGED_DIRECTORY=\"$(pwd)/../forged\"" > .local_envrc
echo "export KUBECONFIG=~/.kube/config" >> .local_envrc
echo 'export PATH="$PATH:$FORGED_DIRECTORY/.binaries/"' >> .local_envrc
echo "export CONTEXT=k3s" >> .local_envrc
direnv allow && eval "$(direnv export bash)"

# Cleanup functions defined at the highest level so they can be run at the end
function cleanup_build_boot_artifacts {
  # the /tmp files need cleaning but all the build files in the repo dir do not, they will get cleaned on job reap
  rm -fr /tmp/bfb-dump/
}

function cleanup_build_containers_last {
  echo "just clean-build-container" && just clean-build-container
  echo "just clean-build-container-k3s" && just clean-build-container-k3s
  echo "just clean-runtime-container-k3s" && just clean-runtime-container-k3s
}

function cleanup_build {
  echo "just rmi" && just rmi
}

# Build the PXE boot-artifacts in the background
{
  # Run the x86_64 build
  echo "Starting build for PXE boot-artifacts (x86_64)..."
  cargo make --cwd pxe build-boot-artifacts-x86-host > "$PXE_BUILD_X86_LOG" 2>&1 || exit_code_x86=$?
  exit_code_x86=${exit_code_x86:-0}
  echo "See $PXE_BUILD_X86_LOG for log dump from the build of build-boot-artifacts-x86-host"

  git submodule deinit -f --all
  git submodule update --init --recursive

  # Run the aarch64 build
  echo "Starting build for PXE boot-artifacts (aarch64)..."
  cargo make --cwd pxe build-boot-artifacts-bfb > "$PXE_BUILD_AARCH_LOG" 2>&1 || exit_code_aarch=$?
  exit_code_aarch=${exit_code_aarch:-0}
  echo "See $PXE_BUILD_AARCH_LOG for log dump from the build of build-boot-artifacts-bfb"

  # Check exit codes and handle failures
  if [[ "$exit_code_x86" -ne 0 ]] || [[ "$exit_code_aarch" -ne 0 ]]; then
    echo "Building build-boot-artifacts-x86-host exited with code $exit_code_x86."
    echo "Building build-boot-artifacts-bfb exited with code $exit_code_aarch."
    echo "ERROR: One or both of the PXE boot-artifacts builds failed. Aborting test..."
    cleanup_build_boot_artifacts    
    exit 1
  else
    echo "SUCCESS: Finished building PXE boot-artifacts (x86 and aarch)."
  fi
} > /tmp/pxe-build.log 2>&1 &
pxe_build_pid=$!
echo "Started background process for PXE boot-artifacts build."

# Build the build container images in the background
{
  echo "just build-container" && just build-container
  echo "just build-container-k3s" && just build-container-k3s
  echo "just runtime-container-k3s" && just runtime-container-k3s

  # TODO: Temporary workaround - manually pull these due to a bug preventing them being pulled during skaffold deploy
  docker pull nvcr.io/nvidian/nvforge-devel/frr:8.5.0
  docker pull nvcr.io/nvidian/nvforge-devel/nvmetal-scout-burn-in:1.3.0
} > "$CONTAINER_BUILD_LOG" 2>&1 &
container_build_pid=$!
echo "Started background process to build the build containers."


########################
### Switch to FORGED ###
########################

# Clone 'forged' repo
rm -rf "${FORGED_DIRECTORY}"
git clone "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/nvmetal/forged.git" "${FORGED_DIRECTORY}"
pushd "${FORGED_DIRECTORY}"
echo "Cloned 'main' branch of Forged repo. Current git commit: $(git rev-parse HEAD)"

# Pull Unbound images
docker pull "$(grep unbound_exporter bases/unbound/deployment.yaml | awk '{print $2}')"
docker pull "$(grep unbound: bases/unbound/deployment.yaml | awk '{print $2}')"

# Bring up the base k3s resources (excludes carbide)
echo "Bringing up the base kubernetes node..."
.gitlab/dev-env-test.sh

# Configure DNS
eval "$(direnv export bash)"
echo "just setup-k3s-env-ips" && just setup-k3s-env-ips
echo "just setup-dns" && just setup-dns
popd


#########################
### Return to CARBIDE ###
#########################

eval "$(direnv export bash)"

# Wait for background process to complete building the build containers
echo "Waiting for container build to complete before continuing (PID: $container_build_pid)..."
wait $container_build_pid || exit_code=$?
exit_code=${exit_code:-0}
echo "See $CONTAINER_BUILD_LOG for log dump from the build of the build containers"

if [[ $exit_code -ne 0 ]]; then
  echo "ERROR: Building the build containers failed with exit code $exit_code. Aborting test..."
  cleanup_build_boot_artifacts
  cleanup_build_containers_last
  exit 1
fi

# Build the carbide images (carbide-dns, carbide-api, etc.)
echo "Building the carbide images..."
echo "just build" && just build

# Wait for boot artifacts to complete before deploying
echo "Waiting for PXE boot-artifacts build to complete before deployment (PID: $pxe_build_pid)..."
wait "$pxe_build_pid" || pxe_exit_code=$?
pxe_exit_code=${pxe_exit_code:-0}
echo "See $PXE_BUILD_AARCH_LOG and $PXE_BUILD_X86_LOG for log dumps from the PXE boot-artifacts builds"

if [[ "$pxe_exit_code" -ne 0 ]]; then
  echo "ERROR: Building the PXE boot-artifacts failed with exit code $pxe_exit_code. Aborting test..."
  cleanup_build_boot_artifacts
  cleanup_build
  cleanup_build_containers_last
  exit 1
fi

# Deploy the images to the k3s node
echo "Deploying the carbide images to k3s..."
mkdir -p pxe/static/blobs/internal/firmware/nvidia/dpu/
touch pxe/static/blobs/internal/firmware/nvidia/dpu/test  # TODO: Remove this touchfile once we have a real host to test
skaffold run

# Verify carbide pods have been created
echo "Checking for existence of expected carbide pods..."
expected_pods=("carbide-api" "carbide-dns" "carbide-dhcp" "carbide-pxe" "forge-unbound" "frrouting")
old_IFS=$IFS && IFS=$' '
actual_pods=$(kubectl get pods --namespace=forge-system -o=json | jq -r '.items[].metadata.name')
IFS=$old_IFS

missing_pod=false
for pattern in "${expected_pods[@]}"; do

  # Check for 2 carbide-api pods (to account for carbide-api-migrate), and 2 carbide-dns pods
  if [[ "$pattern" = "carbide-api" || "$pattern" = "carbide-dns" ]]; then
    pod_count=$(echo "$actual_pods" | grep -c "^$pattern" || true)
    if [[ $pod_count -eq 2 ]]; then
      echo "PASS: 2 pod(s) matching pattern $pattern exist."
    else
      echo "FAIL: $pod_count pod(s) matching pattern $pattern exist. Expected 2."
      missing_pod=true
    fi

  # Check for 1 each of the other carbide pods
  else
    if echo "$actual_pods" | grep -q "^$pattern" || true; then
      echo "PASS: 1 pod(s) matching pattern $pattern exist."
    else
      echo "FAIL: 0 pod(s) matching pattern $pattern exist. Expected 1."
      missing_pod=true
    fi
  fi
done

if [[ "$missing_pod" == "true" ]]; then
  echo "ERROR: There are missing carbide pods. Aborting test..."
  cleanup_build_boot_artifacts
  cleanup_build
  cleanup_build_containers_last
  exit 1
else
  echo "SUCCESS: All expected carbide pods were created."
fi


########################
### Switch to FORGED ###
########################

pushd "${FORGED_DIRECTORY}"
eval "$(direnv export bash)"

# Verify k3s health again now that carbide is deployed
echo "Checking health of all kubernetes resources..."
just check-k3s-resource-health

popd

##########################
#### Return to CARBIDE ###
##########################

eval "$(direnv export bash)"

cleanup_build_boot_artifacts
cleanup_build
cleanup_build_containers_last

echo "SUCCESS: All checks successful for Forge environment bring-up."
