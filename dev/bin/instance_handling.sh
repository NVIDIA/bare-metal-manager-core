#!/bin/bash

if [ $# -ne 3 ]; then
  echo
  echo "Must provide command, api_server_ip and api_server_port as positional arguments"
  echo
  echo "    $0" '[test|create|delete] <api_server_ip> <api_server_port>'
  echo
  exit 1
fi

MAX_RETRY=10
HBN_ROOT=$(cat /tmp/hbn_root)
API_SERVER=$2:$3
DPU_CONFIG_FILE="/tmp/forge-dpu-agent-sim-config.toml"

HOST_MACHINE_ID=$(grpcurl -d '{}' -insecure ${API_SERVER} forge.Forge/FindMachines | python3 -c "import sys,json
data=sys.stdin.read()
j=json.loads(data)
for machine in j['machines']:
  if machine['interfaces'][0]['attachedDpuMachineId']['id'] != machine['interfaces'][0]['machineId']['id']:
    print(machine['interfaces'][0]['machineId']['id'])
    break")

DPU_MACHINE_ID=$(grpcurl -d '{"search_config": {"include_dpus": true, "include_predicted_host": true}}' -insecure ${API_SERVER} forge.Forge/FindMachines | python3 -c "import sys,json
data=sys.stdin.read()
j=json.loads(data)
for machine in j['machines']:
  if machine['interfaces'][0]['attachedDpuMachineId']['id'] == machine['interfaces'][0]['machineId']['id']:
    print(machine['interfaces'][0]['machineId']['id'])
    break")

SEGMENT_ID=$(grpcurl -d '{}' -insecure ${API_SERVER} forge.Forge/FindMachines | python3 -c "import sys,json
data=sys.stdin.read()
j=json.loads(data)
print(j['machines'][0]['interfaces'][0]['segmentId']['value'])")

if [[ "$1" == "test" || "$1" == "create" ]]; then
  # Create Instance
  echo "Creating instance with machine: $HOST_MACHINE_ID, with network segment: $SEGMENT_ID"
  grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}, \"config\": {\"tenant\": {\"tenant_organization_id\": \"MyOrg\", \"user_data\": \"hello\", \"custom_ipxe\": \"chain --autofree https://boot.netboot.xyz\"}, \"network\": {\"interfaces\": [{\"function_type\": \"PHYSICAL\", \"network_segment_id\": {\"value\": \"$SEGMENT_ID\"}}]}}}" -insecure ${API_SERVER} forge.Forge/AllocateInstance
  # Apply the networking configuration
  # TODO: Automate this. Get DPU_MACHINE_ID. HBN_ROOT we should have, it's exported by discover_dpu.sh.
  echo "DPU MACHINE ID: ${DPU_MACHINE_ID}"

  MACHINE_STATE=""
  i=0
  while [[ $MACHINE_STATE != "Assigned/WaitingForNetworkConfig" && $i -lt $MAX_RETRY ]]; do
    echo "Checking machine state. Waiting for it to be in WaitingForNetworkConfig state. Current: $MACHINE_STATE"
    MACHINE_STATE=$(grpcurl -d "{\"id\":\"$HOST_MACHINE_ID\"}" -insecure "${API_SERVER}" forge.Forge/GetMachine | jq ".state" | tr -d '"')
    i=$((i+1))
    sleep 10
  done

  if [[ $i == "$MAX_RETRY" ]]; then
    echo "Even after $MAX_RETRY retries, machine did not reach in WaitingForNetworkConfig state."
    exit 3
  fi
  cargo run -p agent -- --config-path "$DPU_CONFIG_FILE" netconf --dpu-machine-id ${DPU_MACHINE_ID}
 fi

# Check Instance state
INSTANCE_ID=$(grpcurl -d '{}' -insecure ${API_SERVER} forge.Forge/FindInstances | jq ".instances[0].id.value" | tr -d '"')

if [[ -z $INSTANCE_ID ]]; then
  echo "Could not find instance. Exiting."
  exit 10
fi

echo "Instance created/found with ID $INSTANCE_ID"

INSTANCE_STATE=""

if [[ "$1" == "test" || "$1" == "create" ]]; then
  i=0
  while [[ $INSTANCE_STATE != "READY" && $i -lt $MAX_RETRY ]]; do
    sleep 10
    INSTANCE_STATE=$(grpcurl -d "{\"id\": {\"value\": \"$INSTANCE_ID\"}}" -insecure ${API_SERVER} forge.Forge/FindInstances | jq ".instances[0].status.tenant.state" | tr -d '"')
    echo "Checking instance state. Waiting for it to be in READY state. Current: $INSTANCE_STATE"
    i=$((i+1))
  done

  if [[ $i == "$MAX_RETRY" ]]; then
    echo "Even after $MAX_RETRY retries, instance did not come in READY state."
    exit 1
  fi
  echo "Instance is up now in Ready state."

  if [[ "$1" == "create" ]]; then
    exit 0
  fi
fi

# You probably need to run `forge-dpu-agent netconf` at various points for state transitions to happen
# See "Apply the networking configuration" above
if [[ "$1" == "test" || "$1" == "delete" ]]; then
  echo "Deleting instance now. Triggers a reboot."
  grpcurl -d "{\"id\": {\"value\": \"$INSTANCE_ID\"}}" -insecure ${API_SERVER} forge.Forge/ReleaseInstance

  MACHINE_STATE=""
  i=0
  while [[ $MACHINE_STATE != "Assigned/BootingWithDiscoveryImage" && $i -lt $MAX_RETRY ]]; do
    echo "Checking machine state. Waiting for it to be in BootingWithDiscoveryImage state. Current: $MACHINE_STATE"
    MACHINE_STATE=$(grpcurl -d "{\"id\":\"$HOST_MACHINE_ID\"}" -insecure "${API_SERVER}" forge.Forge/GetMachine | jq ".state" | tr -d '"')
    i=$((i+1))
    sleep 10
  done

  if [[ $i == "$MAX_RETRY" ]]; then
    echo "Even after $MAX_RETRY retries, machine did not reach in BootingWithDiscoveryImage state."
    exit 3
  fi

  # Boot host up with discovery image on overlay network.
  echo "Machine comes up, forge-scout tells API that we're back"
  grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure ${API_SERVER} forge.Forge/ForgeAgentControl

  MACHINE_STATE=""
  i=0
  while [[ $MACHINE_STATE != "Assigned/WaitingForNetworkReconfig" && $i -lt $MAX_RETRY ]]; do
    echo "Checking machine state. Waiting for it to be in WaitingForNetworkReconfig state. Current: $MACHINE_STATE"
    MACHINE_STATE=$(grpcurl -d "{\"id\":\"$HOST_MACHINE_ID\"}" -insecure "${API_SERVER}" forge.Forge/GetMachine | jq ".state" | tr -d '"')
    i=$((i+1))
    sleep 10
  done

  if [[ $i == "$MAX_RETRY" ]]; then
    echo "Even after $MAX_RETRY retries, machine did not reach in WaitingForNetworkReconfig state."
    exit 3
  fi

  cargo run -p agent -- --config-path "$DPU_CONFIG_FILE" netconf --dpu-machine-id ${DPU_MACHINE_ID}
  # Boot host up with discovery image on admin network.
  echo "Machine comes up, forge-scout tells API that we're back"
  grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure ${API_SERVER} forge.Forge/ForgeAgentControl

  # Wait until its gone.
  i=0
  INSTANCE_GONE="$INSTANCE_ID"
  while [[ -n "$INSTANCE_GONE" && $i -lt $MAX_RETRY ]]; do
    echo "Waiting for instance to be deleted."
    INSTANCE_GONE=$(grpcurl -d "{\"id\": {\"value\": \"$INSTANCE_ID\"}}" -insecure ${API_SERVER} forge.Forge/FindInstances | grep "$INSTANCE_ID")
    sleep 10
    i=$((i+1))
  done

  if [[ $i == "$MAX_RETRY" ]]; then
    echo "Even after $MAX_RETRY retries, instance is not deleted."
    exit 2
  fi

  # Wait for state change.
  MACHINE_STATE=""
  i=0
  while [[ $MACHINE_STATE != "WaitingForCleanup/HostCleanup" && $i -lt $MAX_RETRY ]]; do
    echo "Checking machine state. Waiting for it to be in Waitingforcleanup state. Current: $MACHINE_STATE"
    MACHINE_STATE=$(grpcurl -d "{\"id\":\"$HOST_MACHINE_ID\"}" -insecure ${API_SERVER} forge.Forge/GetMachine | jq ".state" | tr -d '"')
    i=$((i+1))
    sleep 10
  done

  if [[ $i == "$MAX_RETRY" ]]; then
    echo "Even after $MAX_RETRY retries, machine did not reach in WaitingForCleanup state."
    exit 3
  fi

  # Wait for state change.
  grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure ${API_SERVER} forge.Forge/ForgeAgentControl
  grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure ${API_SERVER} forge.Forge/CleanupMachineCompleted

  MACHINE_STATE=""
  i=0
  while [[ $MACHINE_STATE != "Host/Discovered" && $i -lt $MAX_RETRY ]]; do
    echo "Checking machine state. Waiting for it to be in Host/Discovered state. Current: $MACHINE_STATE"
    MACHINE_STATE=$(grpcurl -d "{\"id\":\"$HOST_MACHINE_ID\"}" -insecure ${API_SERVER} forge.Forge/GetMachine | jq ".state" | tr -d '"')
    i=$((i+1))
    sleep 10
  done

  if [[ $i == "$MAX_RETRY" ]]; then
    echo "Even after $MAX_RETRY retries, machine did not reach in WaitingForCleanup state."
    exit 3
  fi

  # Wait for state change.
  grpcurl -d "{\"machine_id\": {\"id\": \"$HOST_MACHINE_ID\"}}" -insecure ${API_SERVER} forge.Forge/ForgeAgentControl

  i=0
  while [[ $MACHINE_STATE != "Ready" && $i -lt $MAX_RETRY ]]; do
    echo "Checking machine state. Waiting for it to be in Ready state. Current: $MACHINE_STATE"
    MACHINE_STATE=$(grpcurl -d "{\"id\":\"$HOST_MACHINE_ID\"}" -insecure ${API_SERVER} forge.Forge/GetMachine | jq ".state" | tr -d '"')
    sleep 10
    i=$((i+1))
  done

  if [[ $i == "$MAX_RETRY" ]]; then
    echo "Even after $MAX_RETRY retries, machine did not reach in Ready state."
    exit 4
  fi

  echo "Host $HOST_MACHINE_ID is back to Ready state."
fi
