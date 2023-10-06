#!/usr/bin/env bash
set -eo pipefail

# This script can be used to simulate discovering a DPU in the docker-compose setup
# It will use a hardcoded MAC address "00:11:22:33:44:55" (see `dpu_dhcp_discovery.json`) in
# the respective environment directory to perform a DHCP request, and then submits Machine details.
# If you need more than one DPU, you can edit the MAC address in the file and call
# `discover_dpu.sh` again

MAX_RETRY=10
if [ $# -ne 1 ]; then
  echo
  echo "Must provide data directory as positional argument"
  echo
  echo "    $0" '<data_dir>'
  echo
  exit 1
fi

export DISABLE_TLS_ENFORCEMENT=true

DATA_DIR=$1
source $DATA_DIR/envrc

DPU_CONFIG_FILE="/tmp/forge-dpu-agent-sim-config.toml"
BMC_METADATA_FILE=${DATA_DIR}/update_dpu_bmc_metadata.json

simulate_boot() {
  # Simulate the DHCP request of a DPU
  RESULT=`grpcurl -d @ -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/DiscoverDhcp < "${DATA_DIR}/dpu_dhcp_discovery.json"`
  MACHINE_INTERFACE_ID=$(echo $RESULT | jq ".machineInterfaceId.value" | tr -d '"')
  echo "Created Machine Interface with ID $MACHINE_INTERFACE_ID"

  #HACK work-around for k8s NAT of outside network traffic
  REAL_IP=$(${REPO_ROOT}/dev/bin/psql.sh "select address from machine_interface_addresses where interface_id='${MACHINE_INTERFACE_ID}';" | tr -d '[:space:]"')
  echo "Machines real IP: ${REAL_IP}"
  ${REPO_ROOT}/dev/bin/psql.sh "update machine_interface_addresses set address='10.244.0.1';"

  echo "Sending pxe boot request"
  curl "http://$PXE_SERVER_HOST:$PXE_SERVER_PORT/api/v0/pxe/boot?uuid=${MACHINE_INTERFACE_ID}&buildarch=arm64"

  echo "Sending cloud-init request"
  curl "http://$PXE_SERVER_HOST:$PXE_SERVER_PORT/api/v0/cloud-init/user-data"

  echo "Sending DiscoverMachine"
  # Simulate the Machine discovery request of a DPU
  DISCOVER_MACHINE_REQUEST=$(jq --arg machine_interface_id "$MACHINE_INTERFACE_ID" '.machine_interface_id.value = $machine_interface_id' "${DATA_DIR}/dpu_machine_discovery.json")
  RESULT=$(echo $DISCOVER_MACHINE_REQUEST | grpcurl -d @ -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/DiscoverMachine)
  DPU_MACHINE_ID=$(echo $RESULT | jq ".machineId.id" | tr -d '"')
  echo "DPU_MACHINE_ID: ${DPU_MACHINE_ID}"

  echo "Updating BMC Metadata"
  UPDATE_BMC_METADATA=$(jq --arg machine_id "$DPU_MACHINE_ID" '.machine_id.id = $machine_id' "$BMC_METADATA_FILE")
  grpcurl -d "$UPDATE_BMC_METADATA" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/UpdateBMCMetaData

  # Mark discovery complete
  echo "Sending DiscoveryComplete"
  RESULT=$(grpcurl -d "{\"machine_id\": {\"id\": \"$DPU_MACHINE_ID\"}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/DiscoveryCompleted)
  echo "DPU discovery completed. Waiting for it reached in Host/WaitingForDiscovery state."

  ${REPO_ROOT}/dev/bin/psql.sh "update machine_interface_addresses set address='${REAL_IP}';"

  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
  echo "Created DPU Machine with ID $DPU_MACHINE_ID (state: ${MACHINE_STATE})"

  ACTION=$(grpcurl -d "{\"machine_id\": {\"id\": \"$DPU_MACHINE_ID\"}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/ForgeAgentControl | jq -r .action)
  echo "Forge Agent Control Result: $ACTION (state: ${MACHINE_STATE})"

  if [[ "${ACTION}" == "DISCOVERY" ]]
  then
    echo "Performing discovery"
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
    echo "DPU discovery completed: ${RESULT}"
  fi

  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
  echo "Machine State: ${MACHINE_STATE}"
}

echo "simulating first boot"
simulate_boot

MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
while [[ $MACHINE_STATE != "DPU/WaitingForNetworkInstall" ]]; do
  echo "Waiting for DPU state DPU/WaitingForNetworkInstall. Current: $MACHINE_STATE"
  sleep 10
  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
done
echo "State: ${MACHINE_STATE}"

echo "simulating second boot"
simulate_boot

MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
while [[ $MACHINE_STATE != "DPU/WaitingForNetworkConfig" ]]; do
  echo "Waiting for DPU state DPU/WaitingForNetworkConfig. Current: $MACHINE_STATE"
  sleep 10
  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
done
echo "State: ${MACHINE_STATE}"

# Cleanup old dirs
rm -rf /tmp/forge-hbn-chroot-*

# Make a directory to put the HBN files
export HBN_ROOT=/tmp/forge-hbn-chroot-${RANDOM} # export so that instance_handle.sh can use it
echo "$HBN_ROOT" > /tmp/hbn_root
mkdir -p ${HBN_ROOT}/etc/frr
mkdir -p ${HBN_ROOT}/etc/network
mkdir -p ${HBN_ROOT}/etc/supervisor/conf.d
mkdir -p ${HBN_ROOT}/etc/cumulus/acl/policy.d

cat <<!> $DPU_CONFIG_FILE
[forge-system]
api-server = "https://$API_SERVER_HOST:$API_SERVER_PORT"
pxe-server = "http://$PXE_SERVER_HOST:$PXE_SERVER_PORT"
root-ca = "./dev/certs/forge_developer_local_only_root_cert_pem"

[machine]
interface-id = "$MACHINE_INTERFACE_ID"
mac-address = "11:22:33:44:55:66"
hostname = "abc.forge.com"
upgrade-cmd = "apt-get install --yes --only-upgrade forge-dpu=__PKG_VERSION__"

[hbn]
root-dir = "$HBN_ROOT"
skip-reload = true
!

# Apply the networking configuration
#
# TODO: This rebuilds everything locally. Instead put forge-dpu-agent in a container, then
# API_CONTAINER=$(docker ps | grep carbide-api | awk -F" " '{print $NF}')
# docker exec -ti ${API_CONTAINER} /opt/forge-dpu-agent netconf --dpu-machine-id ${DPU_MACHINE_ID}
# 1. First run writes the new config, ask HBN to reload
cargo run -p agent -- --config-path "$DPU_CONFIG_FILE" netconf --dpu-machine-id ${DPU_MACHINE_ID}
echo "HBN files are in ${HBN_ROOT}"
# 2. Second run detects healthy network and reports it
cargo run -p agent -- --config-path "$DPU_CONFIG_FILE" netconf --dpu-machine-id ${DPU_MACHINE_ID}

# Wait until DPU becomes ready
MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
while [[ $MACHINE_STATE != "Host/WaitingForDiscovery" ]]; do
  echo "Waiting for DPU state Host/WaitingForDiscovery. Current: $MACHINE_STATE"
  sleep 10
  MACHINE_STATE=$(grpcurl -d "{\"id\": {\"id\": \"$DPU_MACHINE_ID\"}, \"search_config\": {\"include_dpus\": true}}" -insecure $API_SERVER_HOST:$API_SERVER_PORT forge.Forge/FindMachines | jq ".machines[0].state" | tr -d '"')
done

echo "simulating third boot"
simulate_boot

echo "DPU is up now."
