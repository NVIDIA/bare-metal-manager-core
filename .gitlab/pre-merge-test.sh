#!/usr/bin/env bash

#
# Used in pipeline job 'pre-merge-test'. Designed to run directly on a GitLab runner machine.
#
# This script sets up a single-node Forge control plane kubernetes deployment (from the 'forged' repo), builds the
# carbide images, and deploys those to the node.
# It then checks that the expected carbide pods were created, and that all kubernetes resources are healthy.
#

set -xeuo pipefail
echo "Current working directory is: $(pwd)"

# Configure PATH and other environment variables
source /root/.bashrc
doas chown -R $USER $CARGO_HOME

echo "export FORGED_DIRECTORY=\"$(pwd)/../forged\"" > .local_envrc
echo "export KUBECONFIG=~/.kube/config" >> .local_envrc
echo 'export PATH="$PATH:$FORGED_DIRECTORY/.binaries/"' >> .local_envrc
echo "export CONTEXT=k3s" >> .local_envrc
direnv allow && eval "$(direnv export bash)"

# Build the build container images and pull Unbound images (in a background process)
{
  echo "just build-container" && just build-container
  echo "just build-container-k3s" && just build-container-k3s
  echo "just runtime-container-k3s" && just runtime-container-k3s
  docker pull nvcr.io/nvidian/nvforge/unbound_exporter:7561033
  docker pull nvcr.io/nvidian/nvforge/unbound:3b089e6

  # Temporary workaround: manually pull these due to a bug preventing them being pulled during skaffold deploy
  docker pull nvcr.io/nvidian/nvforge-devel/frr:8.5.0
  docker pull nvcr.io/nvidian/nvforge-devel/nvmetal-scout-burn-in:1.3.0
} > /tmp/container-build.log 2>&1 &
background_pid=$!

# TODO: Once we have an Acorn host included, build these conditionally on whether or not pxe/ and scout/ have changes and remove the touchfile
# cargo make --cwd pxe build-boot-artifacts-x86_64
# cargo make --cwd pxe build-boot-artifacts-aarch64
mkdir -p pxe/static/blobs/internal/firmware/nvidia/dpu/
touch pxe/static/blobs/internal/firmware/nvidia/dpu/test


########################
### Switch to FORGED ###
########################

# Clone 'forged' repo
rm -rf "${FORGED_DIRECTORY}"
git clone "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/nvmetal/forged.git" "${FORGED_DIRECTORY}"
pushd "${FORGED_DIRECTORY}"

# Bring up the base k3s resources (excludes carbide)
.gitlab/dev-env-setup.sh

# Configure DNS
eval "$(direnv export bash)"
echo "just setup-k3s-env-ips" && just setup-k3s-env-ips
echo "just setup-dns" && just setup-dns
popd


#########################
### Return to CARBIDE ###
#########################

eval "$(direnv export bash)"

# Wait for background process to complete building build containers
wait $background_pid
exit_code=$?
echo "Output of background container build:" && cat /tmp/container-build.log

if [[ $exit_code -ne 0 ]]; then
  echo "Building the build containers failed with exit code $exit_code. Aborting test..."
  exit 1
fi

# Build the carbide images (carbide-dns, carbide-api, etc.)
echo "just build" && just build

# Deploy the images to the k3s node
skaffold run

# Verify carbide pods have been created
expected_pods=("carbide-api" "carbide-dns" "carbide-dhcp" "carbide-pxe" "forge-unbound" "frrouting")
old_IFS=$IFS && IFS=$' '
actual_pods=$(kubectl get pods --namespace=forge-system -o=json | jq -r '.items[].metadata.name')
IFS=$old_IFS

set +xe
failure=0
for pattern in "${expected_pods[@]}"; do

  # Check for 2 carbide-api pods (to account for carbide-api-migrate), and 2 carbide-dns pods
  if [[ "$pattern" = "carbide-api" || "$pattern" = "carbide-dns" ]]; then
    pod_count=$(echo "$actual_pods" | grep -c "^$pattern")
    if [[ $pod_count -eq 2 ]]; then
      echo "PASS: 2 pod(s) matching pattern $pattern exist."
    else
      echo "FAIL: $pod_count pod(s) matching pattern $pattern exist. Expected 2."
      failure=1
    fi

  # Check for 1 each of the other carbide pods
  else
    if echo "$actual_pods" | grep -q "^$pattern"; then
      echo "PASS: 1 pod(s) matching pattern $pattern exist."
    else
      echo "FAIL: 0 pod(s) matching pattern $pattern exist. Expected 1."
      failure=1
    fi
  fi
done

if [[ "$failure" -eq 1 ]]; then
  echo "Pod creation: FAIL. There are missing pods. Aborting test..."
  exit 1
else
  echo "Pod creation: PASS. All expected pods were created."
fi

set -xe


########################
### Switch to FORGED ###
########################

pushd "${FORGED_DIRECTORY}"
eval "$(direnv export bash)"

# Verify k3s node health again now that carbide is deployed
just check-k3s-resource-health
