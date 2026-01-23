#!/usr/bin/env sh

# Script to check if all NVMe devices are writeable
# Returns exit code 0 (true) if all NVMe devices are writeable, 1 (false) otherwise

# Get all NVMe devices
nvme_devices=$(lsblk -d -o NAME,TYPE,RO | grep -i nvme | grep disk)

echo "$nvme_devices"
# Check if any are read-only
readonly_nvme=$(echo "$nvme_devices" | grep '1$')

if [ -n "$readonly_nvme" ]; then
    echo "Found read-only NVMe devices:" >&2
    echo "$readonly_nvme" >&2
    exit 1
else
    echo "All NVMe devices are writeable"
    exit 0
fi