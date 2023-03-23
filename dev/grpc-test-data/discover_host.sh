#!/bin/bash
set -eo pipefail

# This script can be used to simulate discovering a Host in the docker-compose setup
# It will use a hardcoded MAC address "00:11:22:33:44:66" (see `host_dhcp_discovery.json`)
# to perform a DHCP request, and then submits Machine details.
# If you need more than one HOST, you can edit the MAC address in the file and call
# `discover_dpu.sh` to create DPU first and `discover_host.sh` to create host again

MAX_RETRY=10
# Determine the CircuitId that our host needs to use
# We use the first network segment that we can find
RESULT=$(grpcurl -insecure 127.0.0.1:1079 forge.Forge/FindNetworkSegments)
CIRCUIT_ID=$(echo "$RESULT" | jq ".networkSegments | .[0] | .prefixes | .[0] | .circuitId" | tr -d '"')
echo "Circuit ID is $CIRCUIT_ID"

# Simulate the DHCP request of a x86 host
# IMPORTANT: This only works a single time, because the loopback IP used in this request is hardcoded
# And that hardcoded IP will only be assigned to the first DPU that is discovered
HOST_DHCP_REQUEST=$(jq --arg circuit_id "$CIRCUIT_ID" '.circuit_id = $circuit_id' "$REPO_ROOT/dev/grpc-test-data/host_dhcp_discovery.json")
RESULT=$(echo "$HOST_DHCP_REQUEST" | grpcurl -d @ -insecure 127.0.0.1:1079 forge.Forge/DiscoverDhcp)
MACHINE_INTERFACE_ID=$(echo "$RESULT" | jq ".machineInterfaceId.value" | tr -d '"')
echo "Created Machine Interface with ID $MACHINE_INTERFACE_ID"

# Simulate the Machine discovery request of a x86 host
DISCOVER_MACHINE_REQUEST=$(jq --arg machine_interface_id "$MACHINE_INTERFACE_ID" '.machine_interface_id.value = $machine_interface_id' "$REPO_ROOT/dev/grpc-test-data/dpu_machine_discovery.json")
DISCOVER_MACHINE_REQUEST=${DISCOVER_MACHINE_REQUEST//aarch64/x86_64}
DISCOVER_MACHINE_REQUEST=${DISCOVER_MACHINE_REQUEST//Dpu123/Host123}
DISCOVER_MACHINE_REQUEST=${DISCOVER_MACHINE_REQUEST//DpuBoard123/HostBoard123}
DISCOVER_MACHINE_REQUEST=${DISCOVER_MACHINE_REQUEST//DpuChassis123/HostChassis123}
DISCOVER_MACHINE_REQUEST=${DISCOVER_MACHINE_REQUEST//DpuProductName234/HostProductName234}
DISCOVER_MACHINE_REQUEST=${DISCOVER_MACHINE_REQUEST//DpuSysVendor234/HostSysVendor234}

# Assuming ManagedHost is Host/Init state now.
RESULT=$(echo "$DISCOVER_MACHINE_REQUEST" | grpcurl -d @ -insecure 127.0.0.1:1079 forge.Forge/DiscoverMachine)
HOST_MACHINE_ID=$(echo "$RESULT" | jq ".machineId.id" | tr -d '"')
grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure 127.0.0.1:1079 forge.Forge/ForgeAgentControl

# Give it a BMC IP and credentials
grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"ip\": \"host.docker.internal:1266\", \"data\": [{\"user\": \"forge_admin\", \"password\": \"notforprod\", \"role\": 1}], \"request_type\": 1 }" -insecure 127.0.0.1:1079 forge.Forge/UpdateBMCMetaData
echo "Created HOST Machine with ID $HOST_MACHINE_ID. Starting discovery and waiting for it to reach in WaitingForDiscovery state."

# Wait until host reaches discovered state.
i=0
MACHINE_STATE=""
while [[ $MACHINE_STATE != "Host/WaitingForDiscovery" && $i -lt $MAX_RETRY ]]; do
  sleep 10
  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure 127.0.0.1:1079 forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
  echo "Checking machine state. Waiting for it to be in Host/WaitingForDiscovery state. Current: $MACHINE_STATE"
  i=$((i+1))
done

if [[ $i == "$MAX_RETRY" ]]; then
  echo "Even after $MAX_RETRY retries, Host did not come in Host/Discovered state."
  exit 1
fi

# Mark discovery complete
RESULT=$(grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure 127.0.0.1:1079 forge.Forge/DiscoveryCompleted)

# Wait until host reaches discovered state.
i=0
MACHINE_STATE=""
while [[ $MACHINE_STATE != "Host/Discovered" && $i -lt $MAX_RETRY ]]; do
  sleep 10
  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure 127.0.0.1:1079 forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
  echo "Checking machine state. Waiting for it to be in Host/Discovered state. Current: $MACHINE_STATE"
  i=$((i+1))
done

if [[ $i == "$MAX_RETRY" ]]; then
  echo "Even after $MAX_RETRY retries, Host did not come in Host/Discovered state."
  exit 1
fi

grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure 127.0.0.1:1079 forge.Forge/ForgeAgentControl

# Wait until host reaches ready state.
i=0
MACHINE_STATE=""
while [[ $MACHINE_STATE != "Ready" && $i -lt $MAX_RETRY ]]; do
  sleep 10
  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure 127.0.0.1:1079 forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
  echo "Checking machine state. Waiting for it to be in Ready state. Current: $MACHINE_STATE"
  i=$((i+1))
done

if [[ $i == "$MAX_RETRY" ]]; then
  echo "Even after $MAX_RETRY retries, Host did not come in Ready state."
  exit 1
fi

echo "ManagedHost is up in Ready state."
