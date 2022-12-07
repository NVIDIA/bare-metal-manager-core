#!/bin/bash
set -eo pipefail

# This script can be used to simulate discovering a Host in the docker-compose setup
# It will use a hardcoded MAC address "00:11:22:33:44:66" (see `host_dhcp_discovery.json`)
# to perform a DHCP request, and then submits Machine details.
# If you need more than one HOST, you can edit the MAC address in the file and call
# `discover_dpu.sh` to create DPU first and `discover_host.sh` to create host again

# Simulate the DHCP request of a DPU
RESULT=$(grpcurl -d @ -plaintext 127.0.0.1:1079 forge.Forge/DiscoverDhcp < "$REPO_ROOT/dev/grpc-test-data/host_dhcp_discovery.json")
MACHINE_INTERFACE_ID=$(echo "$RESULT" | jq ".machineInterfaceId.value" | tr -d '"')
echo "Created Machine Interface with ID $MACHINE_INTERFACE_ID"

# Simulate the Machine discovery request of a DPU
DISCOVER_MACHINE_REQUEST=$(jq --arg machine_interface_id "$MACHINE_INTERFACE_ID" '.machine_interface_id.value = $machine_interface_id' "$REPO_ROOT/dev/grpc-test-data/dpu_machine_discovery.json")
DISCOVER_MACHINE_REQUEST=${DISCOVER_MACHINE_REQUEST//aarch64/x86_64}
RESULT=$(echo "$DISCOVER_MACHINE_REQUEST" | grpcurl -d @ -plaintext 127.0.0.1:1079 forge.Forge/DiscoverMachine)
HOST_MACHINE_ID=$(echo "$RESULT" | jq ".machineId.value" | tr -d '"')
echo "Created HOST Machine with ID $HOST_MACHINE_ID"

# TODO: Simulate credential settings of a Host
