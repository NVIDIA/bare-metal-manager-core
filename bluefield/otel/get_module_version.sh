#!/bin/bash -p

if [ $# -eq 0 ]; then
    echo "Error: go module directory unspecified"
    echo "usage: $0 <module_dir>"
    exit 1
fi

MODULE_DIR=$1
VERSION_FILE="$1/version.go"

if [ ! -f "$VERSION_FILE" ]; then
    echo "Error: $VERSION_FILE not found"
    exit 1
fi

# Extract the version from version.go
VERSION=$(grep -E '^const Version =' "$VERSION_FILE" | sed -E 's/^const Version = "(.+)"$/\1/')
if [ -z "$VERSION" ]; then
    echo "Error: Could not extract version from $VERSION_FILE"
    exit 1
fi

echo "$VERSION"
