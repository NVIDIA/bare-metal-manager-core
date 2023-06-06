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
  echo "Must provide api_server_host, api_server_port and data directory as positional arguments"
  echo
  echo "    $0" '<api_server_host> <api_server_port> <data_dir>'
  echo
  exit 1
fi

API_SERVER_HOST=$1
API_SERVER_PORT=$2
DATA_DIR=$3

DPU_CONFIG_FILE="/tmp/forge-dpu-agent-sim-config.toml"

# Simulate the DHCP request of a DPU
RESULT=`grpcurl -d @ -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/DiscoverDhcp < "${DATA_DIR}/dpu_dhcp_discovery.json"`
MACHINE_INTERFACE_ID=$(echo $RESULT | jq ".machineInterfaceId.value" | tr -d '"')
echo "Created Machine Interface with ID $MACHINE_INTERFACE_ID"

# Simulate the Machine discovery request of a DPU
DISCOVER_MACHINE_REQUEST=$(jq --arg machine_interface_id "$MACHINE_INTERFACE_ID" '.machine_interface_id.value = $machine_interface_id' "${DATA_DIR}/dpu_machine_discovery.json")
RESULT=$(echo $DISCOVER_MACHINE_REQUEST | grpcurl -d @ -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/DiscoverMachine)
DPU_MACHINE_ID=$(echo $RESULT | jq ".machineId.id" | tr -d '"')

echo "Created DPU Machine with ID $DPU_MACHINE_ID"

# Simulate credential settings of a DPU
RESULT=$(grpcurl -d "{\"machine_id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"credentials\": [{\"user\": \"forge\", \"password\": \"notforprod\", \"credential_purpose\": 1}] }" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/UpdateMachineCredentials)
cred_ret=$?
if [ $cred_ret -eq 0 ]; then
	echo "Created 'forge' DPU SSH account"
else
	echo "Failed to create DPU SSH account"
	exit $cred_ret
fi

# Mark discovery complete
RESULT=$(grpcurl -d "{\"machine_id\": {\"id\": \"$DPU_MACHINE_ID\"}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/DiscoveryCompleted)
echo "DPU discovery completed. Waiting for it reached in Host/WaitingForDiscovery state."

# Cleanup old dirs
rm -rf /tmp/forge-hbn-chroot-*

# Make a directory to put the HBN files
export HBN_ROOT=/tmp/forge-hbn-chroot-${RANDOM} # export so that instance_handle.sh can use it
echo "$HBN_ROOT" > /tmp/hbn_root
mkdir -p ${HBN_ROOT}/etc/frr
mkdir -p ${HBN_ROOT}/etc/network
mkdir -p ${HBN_ROOT}/etc/supervisor/conf.d

cat <<!> $DPU_CONFIG_FILE
[forge-system]
api-server = "https://127.0.0.1:1079"
pxe-server = "http://127.0.0.1:8080"
root-ca = "./dev/certs/forge_root.pem"

[machine]
interface-id = "$MACHINE_INTERFACE_ID"
mac-address = "11:22:33:44:55:66"
hostname = "abc.forge.com"
!

# Apply the networking configuration
#
# TODO: This rebuilds everything locally. Instead put forge-dpu-agent in a container, then
# API_CONTAINER=$(docker ps | grep carbide-api | awk -F" " '{print $NF}')
# docker exec -ti ${API_CONTAINER} /opt/forge-dpu-agent netconf --dpu-machine-id ${DPU_MACHINE_ID} --chroot ${HBN_ROOT} --skip-reload
cargo run -p agent -- --config-path "$DPU_CONFIG_FILE" netconf --dpu-machine-id ${DPU_MACHINE_ID} --chroot ${HBN_ROOT} --skip-reload
echo "HBN files are in ${HBN_ROOT}"

# Wait until DPU becomes ready
MACHINE_STATE=""
while [[ $MACHINE_STATE != "Host/WaitingForDiscovery" ]]; do
  sleep 10
  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
  echo "Waiting for DPU state Host/WaitingForDiscovery. Current: $MACHINE_STATE"
done

echo "DPU is up now."
