#!/bin/bash
set -eo pipefail

# This script can be used to simulate discovering a DPU in the docker-compose setup
# It will use a hardcoded MAC address "00:11:22:33:44:55" (see `dpu_dhcp_discovery.json`)
# to perform a DHCP request, and then submits Machine details.
# If you need more than one DPU, you can edit the MAC address in the file and call
# `discover_dpu.sh` again

# Simulate the DHCP request of a DPU
RESULT=`grpcurl -d @ -plaintext 127.0.0.1:1079 forge.Forge/DiscoverDhcp < "$REPO_ROOT/dev/grpc-test-data/dpu_dhcp_discovery.json"`
MACHINE_INTERFACE_ID=$(echo $RESULT | jq ".machineInterfaceId.value" | tr -d '"')
echo "Created Machine Interface with ID $MACHINE_INTERFACE_ID"

# Simulate the Machine discovery request of a DPU
DISCOVER_MACHINE_REQUEST=$(jq --arg machine_interface_id "$MACHINE_INTERFACE_ID" '.machine_id.value = $machine_interface_id' $REPO_ROOT/dev/grpc-test-data/dpu_machine_discovery.json)
RESULT=$(echo $DISCOVER_MACHINE_REQUEST | grpcurl -d @ -plaintext 127.0.0.1:1079 forge.Forge/DiscoverMachine)
DPU_MACHINE_ID=$(echo $RESULT | jq ".machineId.value" | tr -d '"')
echo "Created DPU Machine with ID $DPU_MACHINE_ID"

# TODO: Simulate credential settings of a DPU
