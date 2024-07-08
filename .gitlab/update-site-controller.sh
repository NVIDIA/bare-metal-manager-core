#!/bin/bash
# For use by pipeline job 'scheduled-test:auto-deploy-site-controller'
set -euo pipefail

# Sync Argo CD and wait for health
function sync_argocd() {
  argocd app get --refresh "argocd/site-controller"
  argocd app sync "argocd/site-controller"
  argocd app wait "argocd/site-controller" --sync --timeout 600
  argocd app wait "argocd/site-controller" --health --timeout 600
}

# Git commit, merge & wait for pipeline to complete
function update_git() {
  echo "Committing and merging changes to forged"
  git remote set-url origin "https://oauth2:${FORGED_PROJECT_ACCESS_TOKEN}@${CI_SERVER_HOST}/nvmetal/forged.git"
  git config user.email "dummy@example.com" && git config user.name "Automated Pipeline ${CI_PIPELINE_IID}"
  git commit -am "${FORGED_COMMIT_MSG}"
  git push origin "${FORGED_BRANCH}"
  MR_IID="$(gitlab --server-url "${GITLAB_SERVER_URL_NO_PORT}" --private-token "${FORGED_PROJECT_ACCESS_TOKEN}" project-merge-request create \
    --project-id "${FORGED_PROJECT_ID}" --source-branch "${FORGED_BRANCH}" --target-branch main --title "${FORGED_COMMIT_MSG}" \
    --remove-source-branch true --squash true | cut -d " " -f 2)"

  echo "Waiting up to 2 mins for MR & CI to be ready..."
  MERGE_STATUS_CMD="gitlab --server-url \"${GITLAB_SERVER_URL_NO_PORT}\" --private-token \"${FORGED_PROJECT_ACCESS_TOKEN}\" --verbose project-merge-request list \
    --project-id \"${FORGED_PROJECT_ID}\" --iid \"${MR_IID}\" | grep detailed-merge-status | awk -F ' ' '{print \$2}'"
  timeout=$((SECONDS + 120))
  while true; do
    # If status field hasn't changed to 'ci_still_running' in 2 mins, it's safe to proceed anyway (there appears to be a transient bug in the API)
    if [[ $SECONDS -ge $timeout ]]; then echo "Timeout waiting for MR to be ready, proceeding anyway..."; break; fi
    status=$(eval "${MERGE_STATUS_CMD}")
    if [[ $status == "ci_still_running" ]]; then break; else sleep 5; fi
  done

  gitlab --server-url "${GITLAB_SERVER_URL_NO_PORT}" --private-token "${FORGED_PROJECT_ACCESS_TOKEN}" project-merge-request merge \
    --project-id "${FORGED_PROJECT_ID}" --iid "${MR_IID}" --should-remove-source-branch true --merge-when-pipeline-succeeds true

  echo "Waiting up to 30 mins for MR to be merged..."
  MR_STATE_CMD="gitlab --server-url \"${GITLAB_SERVER_URL_NO_PORT}\" --private-token \"${FORGED_PROJECT_ACCESS_TOKEN}\" --verbose project-merge-request list \
    --project-id \"${FORGED_PROJECT_ID}\" --iid \"${MR_IID}\" | grep \"^state\" | awk -F ' ' '{print \$2}'"
  timeout=$((SECONDS + (60*30)))
  while true; do
    if [[ $SECONDS -ge $timeout ]]; then echo "Error: Timeout waiting for MR to be merged"; exit 1; fi
    state=$(eval "${MR_STATE_CMD}")
    if [[ $state == "merged" ]]; then break; else sleep 60; fi
  done
}

source .gitlab/get-latest-versions.sh

ARGOCD_SITE_PASSWORD="$(vault kv get -field argo-admin-password "secrets/${SITE_UNDER_TEST}")"
FORGED_PROJECT_ACCESS_TOKEN="$(vault kv get -field forged_project_token secrets/forge/tokens)"

ARGOCD_SITE_URL="argocd-${SHORT_SITE_NAME}.frg.nvidia.com"
argocd login "${ARGOCD_SITE_URL}" --username "${ARGOCD_SITE_USERNAME}" --password "${ARGOCD_SITE_PASSWORD}"
echo "Getting initial sync status of Argo CD"
SYNC_STATUS_CMD="argocd app get --refresh argocd/site-controller | grep -P 'carbide-api|carbide-pxe|carbide-dns|carbide-dhcp|carbide-hardware-health|ssh-console'"
INITIAL_SYNC_STATUS=$(eval "${SYNC_STATUS_CMD}")

git clone "https://gitlab-ci-token:${CI_JOB_TOKEN}@${CI_SERVER_HOST}/nvmetal/forged.git" && cd forged
git checkout -b "${FORGED_BRANCH}"
cd envs/"${SITE_UNDER_TEST}"/site/site-controller
kustomize edit set image "${APPLICATION_DOCKER_IMAGE_PRODUCTION}"="${APPLICATION_DOCKER_IMAGE}":"${LATEST_COMMON_VERSION}"
kustomize edit set image "${ARTIFACTS_DOCKER_IMAGE_AARCH64_PRODUCTION}"="${ARTIFACTS_DOCKER_IMAGE_AARCH64}":"${LATEST_COMMON_VERSION}"
kustomize edit set image "${ARTIFACTS_DOCKER_IMAGE_X86_64_PRODUCTION}"="${ARTIFACTS_DOCKER_IMAGE_X86_64}":"${LATEST_COMMON_VERSION}"
kustomize edit set image nvcr.io/nvidian/nvforge/ssh-console=nvcr.io/nvidian/nvforge-devel/ssh-console:"${LATEST_SSH_CONSOLE_VERSION}"

git_status="$(git status --porcelain)"
if [[ -n $git_status ]]; then
  update_git
  if echo "${INITIAL_SYNC_STATUS}" | grep -q "OutOfSync"; then
    echo "Waiting 5 mins to be sure gitlab-master has synced to gitlab cloud..."
    sleep $((60*5))
  else
    echo "Waiting up to 5 mins for Argo CD to go out-of-sync..."
    timeout=$((SECONDS + (60*5)))
    while true; do
      if [[ $SECONDS -ge $timeout ]]; then echo "Error: Timeout waiting 5 mins for Argo CD to go out-of-sync"; exit 1; fi
      sync_status=$(eval "${SYNC_STATUS_CMD}")
      if echo "${sync_status}" | grep -q "OutOfSync"; then echo "Argo CD is now out-of-sync, proceeding to sync..."; break; else sleep 10; fi
    done
  fi
else
  if ! echo "${INITIAL_SYNC_STATUS}" | grep -q "OutOfSync"; then
    echo "${SITE_UNDER_TEST} is already configured for the latest site-controller in forged and Argo CD is in-sync. Nothing to do."; exit 0
  fi
fi
sync_argocd
