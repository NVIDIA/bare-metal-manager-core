#!/bin/bash

set -eux pipefail

GIT_DEPTH=1
echo ${CI_COMMIT_SHA}
echo ${CI_COMMIT_BEFORE_SHA}

git config user.name "HELM_GIT_CI"
git config user.email "project49597_bot1@noreply.gitlab-master.nvidia.com"

#git fetch --depth $GIT_DEPTH origin $CI_MERGE_REQUEST_DIFF_BASE_SHA

#git diff-tree --name-only -r $CI_MERGE_REQUEST_DIFF_BASE_SHA $CI_COMMIT_SHA > CHANGES.txt

git diff-tree --name-only -r ${CI_COMMIT_BEFORE_SHA} $CI_COMMIT_SHA > CHANGES.txt
