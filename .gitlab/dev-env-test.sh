#!/usr/bin/env bash

#
# Used in pipeline job 'dev-env-test'. Designed to run directly on a GitLab runner machine.
#
# This script sets up a single-node Forge control plane kubernetes deployment (from the 'forged' repo), builds the
# carbide images, and deploys those to the node.
# It then checks that the expected carbide pods were created, and that all kubernetes resources are healthy.
#

set -xeuo pipefail
echo "Current working directory is: $(pwd)"

# Merge trunk into branch to improve test reliability
if [[ "$CI_COMMIT_REF_NAME" != "trunk" ]]; then
  echo "Merging 'trunk' into current branch to ensure it's up-to-date..."
  git config user.email "dummy@example.com" && git config user.name "Pre-Merge Test User"
  git fetch origin trunk
  if ! git merge origin/trunk; then
    echo "Merge conflict detected. This must be resolved before the pre-merge test can run. Exiting..."
    exit 1
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

# Conditionally build the PXE boot-artifacts (if the current branch has changes to the relevant files, or if branch is trunk)
directories_pattern="pxe/*|scout/*"
if git diff --name-only HEAD origin/trunk | grep -qE "${directories_pattern}" || [[ "$CI_COMMIT_REF_NAME" = "trunk" ]]; then
  # Sequentially run cargo make commands in the background, and wait for completion at the end
  {
  # Run the x86_64 build
  echo "Starting build for PXE boot-artifacts (x86_64)..."
  cargo make --cwd pxe build-boot-artifacts-x86_64 > /tmp/pxe-build-x86.log 2>&1 || exit_code_x86=$?
  exit_code_x86=${exit_code_x86:-0}
  echo "Log dump from the build of build-boot-artifacts-x86_64: "
  cat /tmp/pxe-build-x86.log

  git submodule deinit -f --all
  git submodule update --init --recursive

  # Run the aarch64 build
  echo "Starting build for PXE boot-artifacts (aarch64)..."
  cargo make --cwd pxe build-boot-artifacts-aarch64 > /tmp/pxe-build-aarch.log 2>&1 || exit_code_aarch=$?
  exit_code_aarch=${exit_code_aarch:-0}
  echo "Log dump from the build of build-boot-artifacts-aarch64: "
  cat /tmp/pxe-build-aarch.log

  # Check exit codes and handle failures
  if [[ "$exit_code_x86" -ne 0 ]] || [[ "$exit_code_aarch" -ne 0 ]]; then
    echo "Building build-boot-artifacts-x86_64 exited with code $exit_code_x86."
    echo "Building build-boot-artifacts-aarch64 exited with code $exit_code_aarch."
    echo "ERROR: One or both of the PXE boot-artifacts builds failed. Aborting test..."
    exit 1
  else
    echo "SUCCESS: Finished building PXE boot-artifacts (x86 and aarch)."
  fi
  } > /tmp/pxe-build.log 2>&1 &
  pxe_build_pid=$!
  echo "Started background process for PXE boot-artifacts build."
  pxe_build=true
else
  echo "No changes in pxe/* or scout/*. Skipping build of PXE boot-artifacts..."
  pxe_build=false
fi

# Build the build container images in the background
{
  echo "just build-container" && just build-container
  echo "just build-container-k3s" && just build-container-k3s
  echo "just runtime-container-k3s" && just runtime-container-k3s

  # TODO: Temporary workaround - manually pull these due to a bug preventing them being pulled during skaffold deploy
  docker pull nvcr.io/nvidian/nvforge-devel/frr:8.5.0
  docker pull nvcr.io/nvidian/nvforge-devel/nvmetal-scout-burn-in:1.3.0
} > /tmp/container-build.log 2>&1 &
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
echo "Log dump from the background build of the build containers: "
cat /tmp/container-build.log

if [[ $exit_code -ne 0 ]]; then
  echo "ERROR: Building the build containers failed with exit code $exit_code. Aborting test..."
  exit 1
fi

# Build the carbide images (carbide-dns, carbide-api, etc.)
echo "Building the carbide images..."
echo "just build" && just build

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

# Finally wait for the PXE boot-artifacts builds to complete (if applicable)
if [[ "$pxe_build" == "true" ]]; then
  echo "Waiting for PXE boot-artifacts build to complete before continuing (PID: $pxe_build_pid)..."
  wait "$pxe_build_pid" || pxe_exit_code=$?
  pxe_exit_code=${pxe_exit_code:-0}
  echo "Log dump from the PXE boot-artifacts build: "
  cat /tmp/pxe-build.log

  if [[ "$pxe_exit_code" -ne 0 ]]; then
    echo "ERROR: Building the PXE boot-artifacts failed with exit code $pxe_exit_code. Aborting test..."
    exit 1
  fi
fi

echo "SUCCESS: All checks successful for Forge environment bring-up."
