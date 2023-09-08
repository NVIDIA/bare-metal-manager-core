#!/bin/bash
set -eo pipefail

# This script can be used to simulate discovering a Host in the docker-compose setup
# It will use a hardcoded MAC address "00:11:22:33:44:66" (see `host_dhcp_discovery.json` in
# the respective env directory) to perform a DHCP request, and then submits Machine details.
# If you need more than one HOST, you can edit the MAC address in the file and call
# `discover_dpu.sh` to create DPU first and `discover_host.sh` to create host again

MAX_RETRY=20
if [ $# -ne 4 ]; then
  echo
  echo "Must provide api_server_host, api_server_port, data directory and discovery mode as positional arguments"
  echo
  echo "    $0" '<api_server_host> <api_server_port> <data_dir> [full|dhcp-only]'
  echo
  exit 1
fi

export DISABLE_TLS_ENFORCEMENT=true

API_SERVER_HOST=$1
API_SERVER_PORT=$2
HOST_DHCP_FILE=$3/host_dhcp_discovery.json
HOST_MACHINE_FILE=$3/host_machine_discovery.json
BMC_METADATA_FILE=$3/update_host_bmc_metadata.json
DISCOVERY_MODE=$4

# Relies on the assumption that the DPU is the only entry
DPU_INFO=$(grpcurl -d "{\"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines)
DPU_MACHINE_ID=$(jq -rn "${DPU_INFO}.machines[0].interfaces[0].machineId.id")
DPU_INTERFACE_ID=$(jq -rn "${DPU_INFO}.machines[0].interfaces[0].id.value")
echo "DPU machine id: ${DPU_MACHINE_ID}"
echo "DPU interface id: ${DPU_INTERFACE_ID}"

HBN_ROOT=$(cat /tmp/hbn_root)
DPU_CONFIG_FILE="/tmp/forge-dpu-agent-sim-config.toml"

# Determine the CircuitId that our host needs to use
# We use the first network segment that we can find
RESULT=$(grpcurl -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindNetworkSegments)
CIRCUIT_ID=$(echo "$RESULT" | jq ".networkSegments | .[0] | .prefixes | .[0] | .circuitId" | tr -d '"')
echo "Circuit ID is $CIRCUIT_ID"

# Simulate the DHCP request of a x86 host
# IMPORTANT: This only works a single time, because the loopback IP used in this request is hardcoded
# And that hardcoded IP will only be assigned to the first DPU that is discovered
HOST_DHCP_REQUEST=$(jq --arg circuit_id "$CIRCUIT_ID" '.circuit_id = $circuit_id' "$HOST_DHCP_FILE")
RESULT=$(echo "$HOST_DHCP_REQUEST" | grpcurl -d @ -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/DiscoverDhcp)
MACHINE_INTERFACE_ID=$(echo "$RESULT" | jq ".machineInterfaceId.value" | tr -d '"')
echo "Using Machine Interface with ID $MACHINE_INTERFACE_ID"
if [ "${DISCOVERY_MODE}" == "dhcp-only" ]
then
  exit 0
fi

# Simulate the Machine discovery request of a x86 host
DISCOVER_MACHINE_REQUEST=$(jq --arg machine_interface_id "$MACHINE_INTERFACE_ID" '.machine_interface_id.value = $machine_interface_id' "$HOST_MACHINE_FILE")

# Assuming ManagedHost is Host/Init state now.
RESULT=$(echo "$DISCOVER_MACHINE_REQUEST" | grpcurl -d @ -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/DiscoverMachine)
HOST_MACHINE_ID=$(echo "$RESULT" | jq ".machineId.id" | tr -d '"')
ACTION=$(grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/ForgeAgentControl | jq -r .action)
echo "Forge agent control: ${ACTION}"

# Give it a BMC IP and credentials
UPDATE_BMC_METADATA=$(jq --arg machine_id "$HOST_MACHINE_ID" '.machine_id.id = $machine_id' "$BMC_METADATA_FILE")
grpcurl -d "$UPDATE_BMC_METADATA" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/UpdateBMCMetaData
echo "Created HOST Machine with ID $HOST_MACHINE_ID. Starting discovery."

MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
echo "State: ${MACHINE_STATE}"
ACTION=$(grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/ForgeAgentControl | jq -r .action)
echo "Host Forge agent control: ${ACTION}"
ACTION=$(grpcurl -d "{\"machine_id\": {\"id\": \"$DPU_MACHINE_ID\"}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/ForgeAgentControl | jq -r .action)
echo "DPU Forge agent control: ${ACTION}"

# Mark discovery complete
RESULT=$(grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/DiscoveryCompleted)

# Wait past the enforced delay until we look for DPU to have rebooted
i=0
while [[ $i -lt $MAX_RETRY ]]; do
  sleep 4

  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
  if [[ "$MACHINE_STATE" == *WaitForDPUUp* ]]; then
	  break
  fi
  echo "Checking machine state. Waiting for it to be in WaitForDPUUp state. Current: $MACHINE_STATE"
  i=$((i+1))
done
if [[ $i -ge "$MAX_RETRY" ]]; then
  echo "Even after $MAX_RETRY retries, Host did not come in WaitForDPUUp state."
  exit 1
fi

MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
echo "State: ${MACHINE_STATE}"

# Run forge-dpu-agent to report an observation, which shows that DPU has now rebooted
cd ${REPO_ROOT} && cargo run -p agent -- --config-path "$DPU_CONFIG_FILE" netconf --dpu-machine-id ${DPU_MACHINE_ID}

# Wait until host reaches discovered state.
i=0
MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
while [[ $MACHINE_STATE != "Host/Discovered" && $MACHINE_STATE != "Ready" && $i -lt $MAX_RETRY ]]; do
  sleep 4

  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
  echo "Checking machine state. Waiting for it to be in Host/Discovered or Ready state. Current: $MACHINE_STATE"
  i=$((i+1))
done

if [[ $i -ge "$MAX_RETRY" ]]; then
  echo "Even after $MAX_RETRY retries, Host did not come in Host/Discovered state."
  exit 1
fi

grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/ForgeAgentControl

# Wait until host reaches ready state.
i=0
while [[ $MACHINE_STATE != "Ready" && $i -lt $MAX_RETRY ]]; do
  sleep 2

  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
  echo "Checking machine state. Waiting for it to be in Ready state. Current: $MACHINE_STATE"
  i=$((i+1))
done

if [[ $i -ge "$MAX_RETRY" ]]; then
  echo "Even after $MAX_RETRY retries, Host did not come in Ready state."
  exit 1
fi

echo "ManagedHost is up in Ready state."
