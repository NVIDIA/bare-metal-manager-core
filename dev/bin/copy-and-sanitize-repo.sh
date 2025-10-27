#!/bin/bash

set -euo pipefail

: "${INITIAL_BRANCH:=main}"

cat <<-EOF
================================================================================
| This script will take the entire contents of the carbide repo and copy it to |
| a new repo, while sanitizing things by removing anything sensitive from the  |
| result. The goal is to deliver a copy of the code for carbide for partners   |
| to inspect (not necessarily as a supported configuration, mostly just for    |
| code reading.)                                                               |
|                                                                              |
| The resulting sanitized copy should build properly but otherwise there are   |
| no guarantees about whether it will work in a real environment.              |
================================================================================
EOF

if [[ -z "${1:-}" ]]
then
    echo "Usage: $0 <dest-dir>"
    exit 1
fi

# Canonicalize $DEST path before cd to repo root
DEST="$(realpath "${1}")"

# cd to repo root
cd "$(dirname "${0}")/../.."

# Ensure we're where we think we are
if ! grep -q carbide-api Cargo.lock
then
    echo "Looks like this script is not in the carbide repo? Aborting."
    exit 1
fi

# Make sure we're not copying into this repo
if [[ "${DEST}" == "$(realpath "$(pwd)")/*" ]]
then
    echo "${DEST} is a subdirectory of this repo. Aborting."
    exit 1
fi

if [[ -e "${DEST}" ]]
then
    # It already exists - make sure it already has a .git directory
    if [[ ! -e "${DEST}/.git" ]]
    then
        cat <<-EOM
${DEST} does not have a git directory, this is likely a mistake. Either let
this script create a new directory, or point it at an existing git repo.

Aborting.
EOM
        exit 1
    fi

    echo "WARNING: The contents of ${DEST} will be removed, and only the .git directory (if any) will be kept. Press \"y\" to continue."
    read -sN 1 confirm
    if [[ "${confirm}" != "y" ]]
    then
        echo "Aborting."
        exit 1
    fi
else
    echo "Creating git repo in ${DEST}"
    mkdir -p "${DEST}"
    (cd "${DEST}" && git init --initial-branch "${INITIAL_BRANCH}")
fi


# Clear the contents of $DEST
(
    cd "${DEST}"
    find "${DEST}" -mindepth 1 -maxdepth 1 -not -path "${DEST}/.git" -a -not -name . -print0 | xargs -r0 rm -rf
)

# Copy from what's in git, excluding from the deny-list
rsync -a \
    --exclude-from=dev/sanitize-denylist.txt \
    --files-from=<(git -c core.quotepath=off ls-files --recurse-submodules) \
    . \
    "${DEST}"/

# Copy the .git dir of each module
mkdir -p "${DEST}/pxe/ipxe/upstream"
cp -a pxe/ipxe/upstream/.git "${DEST}/pxe/ipxe/upstream"
mkdir -p "${DEST}/.git/modules/pxe/ipxe"
cp -a .git/modules/pxe/ipxe/upstream "${DEST}/.git/modules/pxe/ipxe"
mkdir -p "${DEST}/pxe/mkosi"
cp -a pxe/mkosi/.git "${DEST}/pxe/mkosi"
cp -a .git/modules/mkosi "${DEST}/.git/modules"

# Create our own readme without a bunch of jira links
cat >"${DEST}/README.md" <<-EOF
# Carbide - Bare Metal Provisioning

Carbide is a bare metal provisioning system used to manage the lifecycle of
bare metal machines.
EOF

cat <<-EOM
Repo copied. You can now run \`git add -A && git commit -m "Initial commit"\` or similar inside ${DEST}.
EOM
