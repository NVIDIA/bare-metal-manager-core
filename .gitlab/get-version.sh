#!/bin/bash
set -euxo pipefail

git fetch --tags
set +u
if [[ -z "$CI_COMMIT_TAG" ]]; then
    echo "VERSION=$(git describe --tags --first-parent --always)"
    echo "HELM_VERSION=$((git describe --tags --first-parent --always)|sed 's/\(.*\)-/\1\./'))"
else
    echo "VERSION=$CI_COMMIT_TAG"
    echo "HELM_VERSION=$CI_COMMIT_TAG"
fi
set -u

