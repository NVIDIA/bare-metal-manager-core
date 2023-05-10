#!/usr/bin/env bash
set -eo pipefail

# This script can be used to simulate discovering a DPU in the docker-compose setup
# It will use a hardcoded MAC address "00:11:22:33:44:55" (see `dpu_dhcp_discovery.json`) in
# the respective environment directory to perform a DHCP request, and then submits Machine details.
# If you need more than one DPU, you can edit the MAC address in the file and call
# `discover_dpu.sh` again

MAX_RETRY=10
if [ $# -ne 3 ]; then
  echo
  echo "Must provide api_server_ip, api_server_port and data directory as positional arguments"
  echo
  echo "    $0" '<api_server_ip> <api_server_port> <data_dir>'
  echo
  exit 1
fi

API_SERVER_IP=$1
API_SERVER_PORT=$2
DATA_DIR=$3

# Simulate the DHCP request of a DPU
RESULT=`grpcurl -d @ -insecure $API_SERVER_IP:$API_SERVER_PORT forge.Forge/DiscoverDhcp < "${DATA_DIR}/dpu_dhcp_discovery.json"`
MACHINE_INTERFACE_ID=$(echo $RESULT | jq ".machineInterfaceId.value" | tr -d '"')
echo "Created Machine Interface with ID $MACHINE_INTERFACE_ID"

# Simulate the Machine discovery request of a DPU
DISCOVER_MACHINE_REQUEST=$(jq --arg machine_interface_id "$MACHINE_INTERFACE_ID" '.machine_interface_id.value = $machine_interface_id' "${DATA_DIR}/dpu_machine_discovery.json")
RESULT=$(echo $DISCOVER_MACHINE_REQUEST | grpcurl -d @ -insecure $API_SERVER_IP:$API_SERVER_PORT forge.Forge/DiscoverMachine)
DPU_MACHINE_ID=$(echo $RESULT | jq ".machineId.id" | tr -d '"')

echo "Created DPU Machine with ID $DPU_MACHINE_ID"

# Simulate credential settings of a DPU
RESULT=$(grpcurl -d "{\"machine_id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"credentials\": [{\"user\": \"forge\", \"password\": \"notforprod\", \"credential_purpose\": 1}] }" -insecure $API_SERVER_IP:$API_SERVER_PORT forge.Forge/UpdateMachineCredentials)
cred_ret=$?
if [ $cred_ret -eq 0 ]; then
	echo "Created 'forge' DPU SSH account"
else
	echo "Failed to create DPU SSH account"
	exit $cred_ret
fi

# Mark discovery complete
RESULT=$(grpcurl -d "{\"machine_id\": {\"id\": \"$DPU_MACHINE_ID\"}}" -insecure $API_SERVER_IP:$API_SERVER_PORT forge.Forge/DiscoveryCompleted)
echo "DPU discovery completed. Waiting for it reached in Host/WaitingForDiscovery state."

# Wait until DPU becomes ready
i=0
MACHINE_STATE=""
while [[ $MACHINE_STATE != "Host/WaitingForDiscovery" && $i -lt $MAX_RETRY ]]; do
  sleep 10
  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_IP:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
  echo "Checking machine state. Waiting for it to be in Host/WaitingForDiscovery state. Current: $MACHINE_STATE"
  i=$((i+1))
done

if [[ $i == "$MAX_RETRY" ]]; then
  echo "Even after $MAX_RETRY retries, DPU did not come in Host/WaitingForDiscovery state."
  exit 1
fi

echo "DPU is up now."
