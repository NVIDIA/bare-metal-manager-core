#!/bin/bash
# For use by pipeline job 'scheduled-test:auto-deploy-site-controller'
set -euo pipefail

TESTABLE_VERSION_PATTERN='^v\d{4}\.\d{2}\.\d{2}-rc\d+-\d+-\d+-g\w+$'  # Filter out any build version without a git hash

# Set grep regex flag depending on platform
if [[ "$OSTYPE" == "darwin"* ]]; then
    GREP_FLAG="-E"  # MacOS
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    GREP_FLAG="-P"  # GNU Linux
fi

# Get latest 20 build versions from nvcr.io that match pattern "vYYYY.MM.DD-rc0-0-0-gdeadbee"
CARBIDE_VERSIONS="$(crane ls "${APPLICATION_DOCKER_IMAGE:-nvcr.io/nvidian/nvforge-devel/nvmetal-carbide}" | grep "${GREP_FLAG:-'-P'}" ${TESTABLE_VERSION_PATTERN} | sort -V | tail -n 20 | tac)"
BOOT_AARCH64_VERSIONS="$(crane ls "${ARTIFACTS_DOCKER_IMAGE_AARCH64:-nvcr.io/nvidian/nvforge-devel/boot-artifacts-aarch64}" | grep "${GREP_FLAG:-'-P'}" ${TESTABLE_VERSION_PATTERN} | sort -V | tail -n 20 | tac)"
BOOT_X86_VERSIONS="$(crane ls "${ARTIFACTS_DOCKER_IMAGE_X86_64:-nvcr.io/nvidian/nvforge-devel/boot-artifacts-x86_64}" | grep "${GREP_FLAG:-'-P'}" ${TESTABLE_VERSION_PATTERN} | sort -V | tail -n 20 | tac)"
SSH_CONSOLE_VERSIONS="$(crane ls "${DEV_NVCR_BASE:-nvcr.io/nvidian/nvforge-devel}"/ssh-console | grep "${GREP_FLAG:-'-P'}" ${TESTABLE_VERSION_PATTERN} | sort -V | tail -n 20 | tac)"

# Find latest common version of carbide artifacts that exist in `trunk` (i.e. filter out private builds)
LATEST_COMMON_VERSION=""
for version in ${CARBIDE_VERSIONS}; do
  git_hash=$(awk -F'-g' '{print $2}' <<< "$version")
  git log origin/trunk | grep "$git_hash" > /dev/null || continue
  if [[ $(echo "${BOOT_AARCH64_VERSIONS}" | grep -c "\<$version\>") -gt 0 ]] && [[ $(echo "${BOOT_X86_VERSIONS}" | grep -c "\<$version\>") -gt 0 ]]; then
    export LATEST_COMMON_VERSION=$version
    echo "Found latest version of carbide: ${LATEST_COMMON_VERSION}"
    break
  fi
done
if [[ -z "${LATEST_COMMON_VERSION}" ]]; then
  echo "Error: There is no common version across the latest 20 versions of nvmetal-carbide, boot-artifacts-aarch64, and boot-artifacts-x86_64."
  exit 1
fi

# Find latest version of ssh-console that exists in `main` (i.e. filter out private builds)
GITLAB_API_TOKEN=$(vault kv get -field scheduled_pipeline_bot_token secrets/forge/tokens)
LATEST_SSH_CONSOLE_VERSION=""
for version in ${SSH_CONSOLE_VERSIONS}; do
  git_hash=$(awk -F'-g' '{print $2}' <<< "$version")
  curl -s --header "PRIVATE-TOKEN: ${GITLAB_API_TOKEN}" "${CI_API_V4_URL:-"https://gitlab-master.nvidia.com/api/v4"}/projects/80850/repository/commits?ref_name=main" | \
    jq --raw-output '.[] | .short_id? // empty' | grep "$git_hash" > /dev/null || continue
  export LATEST_SSH_CONSOLE_VERSION=$version
  echo "Found latest version of ssh-console: ${LATEST_SSH_CONSOLE_VERSION}"
done
if [[ -z "${LATEST_SSH_CONSOLE_VERSION}" ]]; then
  echo "Error: None of the latest 20 versions of ssh-console was built from the main branch."
  exit 1
fi

echo "LATEST_COMMON_VERSION=${LATEST_COMMON_VERSION}" > versions.env
echo "LATEST_SSH_CONSOLE_VERSION=${LATEST_SSH_CONSOLE_VERSION}" >> versions.env
