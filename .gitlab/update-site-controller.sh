#!/usr/bin/env bash

#
# Used in pipeline job 'scheduled-test:auto-deploy-site-controller'
#
# This script deploys the latest versions of carbide and ssh-console to the site under test (if not already there) by
# updating the `forged` repo and syncing Argo CD.
#

set -euo pipefail


#
# Function to sync Argo CD and wait for health
#
function sync_argocd() {
  # Refresh app state first
  argocd app get --refresh "argocd/site-controller"
  
  # Sync Argo with retries if we get "operation in progress" error
  local max_attempts=6
  for ((i=1; i<=max_attempts; i++)); do
    echo "Sync attempt ${i}/${max_attempts}..."
    
    # Attempt sync and capture output for error checking
    if output=$(argocd app sync "argocd/site-controller" --prune 2>&1); then
      echo "Sync initiated successfully, waiting for completion..."
      argocd app wait "argocd/site-controller" --sync --timeout 600
      argocd app wait "argocd/site-controller" --health --timeout 600
      echo "Argo sync completed successfully!"
      return 0
    fi
    
    # Check if we got the "operation in progress" error
    if echo "${output}" | grep -q "another operation is already in progress"; then
      if [[ $i -lt $max_attempts ]]; then
        echo "Another operation is in progress, waiting 10 seconds before retry..."
        sleep 60
      else
        echo "All attempts failed: another operation is still in progress after 1 minute"
        return 1
      fi
    else
      echo -e "Argo sync failed with unforeseen error: \n${output}"
      return 1
    fi
  done
}

# Get the latest build versions of the carbide artifacts and ssh-console
source .gitlab/get-latest-versions.sh

FORGED_COMMIT_MSG="chore(${SITE_UNDER_TEST}): auto-update site-controller to ${LATEST_COMMON_VERSION}"
FORGED_PROJECT_ACCESS_TOKEN="$(vault kv get -field forged_project_token secrets/forge/tokens)"

ARGOCD_SITE_URL="argocd-${SHORT_SITE_NAME}.frg.nvidia.com"
ARGOCD_SITE_USERNAME="admin"
ARGOCD_SITE_PASSWORD="$(vault kv get -field argo-admin-password "secrets/${SITE_UNDER_TEST}")"

# Get initial status of Argo CD
argocd login "${ARGOCD_SITE_URL}" --username "${ARGOCD_SITE_USERNAME}" --password "${ARGOCD_SITE_PASSWORD}"
echo "Getting initial sync status of Argo CD"
SYNC_STATUS_CMD="argocd app get --refresh argocd/site-controller | grep -P 'carbide-api|carbide-pxe|carbide-dns|carbide-dhcp|carbide-hardware-health|ssh-console'"
INITIAL_SYNC_STATUS=$(eval "${SYNC_STATUS_CMD}")
echo -e "Initial Argo CD sync status: \n${INITIAL_SYNC_STATUS}"

# Clone and make edits to forged
echo "Cloning forged and running kustomize edit..."
git clone "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/nvmetal/forged.git" && cd forged
git checkout main
cd envs/"${SITE_UNDER_TEST}"/site/site-controller
kustomize edit set image "${APPLICATION_DOCKER_IMAGE_PRODUCTION}"="${APPLICATION_DOCKER_IMAGE}":"${LATEST_COMMON_VERSION}"
kustomize edit set image "${ARTIFACTS_DOCKER_IMAGE_AARCH64_PRODUCTION}"="${ARTIFACTS_DOCKER_IMAGE_AARCH64}":"${LATEST_COMMON_VERSION}"
kustomize edit set image "${ARTIFACTS_DOCKER_IMAGE_X86_64_PRODUCTION}"="${ARTIFACTS_DOCKER_IMAGE_X86_64}":"${LATEST_COMMON_VERSION}"
kustomize edit set image nvcr.io/nvidian/nvforge/nvmetal-scout-burn-in=nvcr.io/nvidian/nvforge-devel/machine_validation:"${LATEST_COMMON_VERSION}"
kustomize edit set image nvcr.io/nvidian/nvforge/ssh-console=nvcr.io/nvidian/nvforge-devel/ssh-console:"${LATEST_SSH_CONSOLE_VERSION}"

# If git status is dirty, push directly to main then sync Argo CD. Else just sync Argo CD if needed.
git_status="$(git status --porcelain)"
echo -e "Git status: \n${git_status}"
if [[ -n $git_status ]]; then
  echo "Git status is dirty, proceeding to commit and push to main..."
  git remote set-url origin "https://oauth2:${FORGED_PROJECT_ACCESS_TOKEN}@${CI_SERVER_HOST}/nvmetal/forged.git"
  git config user.email "dummy@example.com" && git config user.name "Automated Pipeline ${CI_PIPELINE_IID}"
  git commit -am "${FORGED_COMMIT_MSG}"
  git pull --rebase origin main  # Resilience against remote being ahead of local branch
  git push origin main
  if echo "${INITIAL_SYNC_STATUS}" | grep -q "OutOfSync"; then
    echo "Waiting 5 mins to be sure gitlab-master has synced to gitlab cloud..."
    sleep $((60*5))
  else
    echo "Waiting up to 5 mins for Argo CD to go out-of-sync..."
    timeout=$((SECONDS + (60*5)))
    while true; do
      if [[ $SECONDS -ge $timeout ]]; then
        echo "Error: Timeout waiting 5 mins for Argo CD to go out-of-sync"
        exit 1
      fi
      sync_status=$(eval "${SYNC_STATUS_CMD}")
      if echo "${sync_status}" | grep -q "OutOfSync"; then
        echo "Argo CD is now out-of-sync, proceeding to sync..."
        break
      else
        sleep 10
      fi
    done
  fi
else
  echo "Git status is clean so ${SITE_UNDER_TEST} is already configured with the latest carbide version in forged."
  if ! echo "${INITIAL_SYNC_STATUS}" | grep -q "OutOfSync"; then
    echo "Argo CD is already in-sync. Nothing to do. Exiting..."
    exit 0
  fi
fi
echo "Performing Argo CD sync..."
sync_argocd
