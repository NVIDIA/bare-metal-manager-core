#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -e

# Arguments:
# $1: Source Org
# $2: Source Team
# $3: Resource Name
# $4: Source Tag
# $5: Semantic Version (Dest Tag)

SOURCE_ORG="$1"
SOURCE_TEAM="$2"
RESOURCE_NAME="$3"
SOURCE_TAG="$4"
SEMANTIC_VERSION="$5"

# TODO: rename to "nico" once the NGC team is created under the org
DEST_TEAM="carbide"

mkdir -p ~/.ngc
mkdir -p download_temp

function push_ngc_resouce {
    resource_org="$1"
    resource_team="$2"
    resource_name="$3"
    version="$4"
    file_path="$5"
    resource_fqn="$resource_org/$resource_team/$resource_name"
    resource_id="$resource_fqn:$version"
    
    if ngc registry resource info "$resource_fqn" >/dev/null 2>&1; then
        echo "Resource $resource_fqn already exists. Updating metadata."
        subcommand="update"
    else
        echo "Resource $resource_fqn not found. Creating a new one."
        subcommand="create"
    fi

    ngc registry resource "$subcommand" \
    --display-name "$resource_name" \
    --short-desc "" \
    --application "OTHER" \
    --framework "Other" \
    --format "generic" \
    --precision "OTHER" \
    "$resource_fqn"

    ngc registry resource upload-version --source "$file_path" "$resource_id"
}

echo "Processing $RESOURCE_NAME (Source: $SOURCE_TAG -> Dest: $SEMANTIC_VERSION)"

echo "Downloading $RESOURCE_NAME:$SOURCE_TAG from $SOURCE_TEAM..."
export NGC_CLI_API_KEY=${SOURCE_TOKEN} NGC_CLI_ORG=$SOURCE_ORG NGC_CLI_TEAM=$SOURCE_TEAM
rm -rf download_temp/*

ngc registry resource download-version "${SOURCE_ORG}/${SOURCE_TEAM}/${RESOURCE_NAME}:${SOURCE_TAG}" --dest download_temp --org "$SOURCE_ORG" --team "$SOURCE_TEAM"

FILE_PATH=$(find download_temp -type f | head -n 1)
if [ -f "$FILE_PATH" ]; then
    echo "Uploading to nico/$RESOURCE_NAME:$SEMANTIC_VERSION..."
    export NGC_CLI_API_KEY=${DEST_TOKEN} NGC_CLI_ORG=$SOURCE_ORG NGC_CLI_TEAM=$DEST_TEAM
    push_ngc_resouce "$SOURCE_ORG" "$DEST_TEAM" "$RESOURCE_NAME" "$SEMANTIC_VERSION" "$FILE_PATH"
else
    echo "Error: File not found after download."
    exit 1
fi

