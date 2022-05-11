#!/usr/bin/env bash

#
# Copyright 2021 NVIDIA CORPORATION & AFFILIATES.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CLUSTER_NAME=""
NUM_WORKERS=2
DHCPD_CONTAINER="vpc_dhcpd"
IMAGES="quay.io/nvidia/nvmetal-hydrazine:latest"

set -eo pipefail
function echoerr {
    >&2 echo "$@"
}

_usage="
Usage: $0 create|destroy|help
where:
  create: create a kind cluster with name CLUSTER_NAME
  destroy: delete a kind cluster with name CLUSTER_NAME
"

function print_usage {
    echoerr "$_usage"
}

function print_help {
    echoerr "Try '$0 help' for more information."
}


function create {
  if [[ -z $CLUSTER_NAME ]]; then
    echoerr "cluster-name not provided"
    exit 1
  fi

  # Having a simple validation check for now.
  # TODO: Making this comprehensive check confirming with rfc1035/rfc1123
  if [[ "$CLUSTER_NAME" =~ [^a-z0-9-] ]]; then
     echoerr "Invalid string. Conform to rfc1035/rfc1123"
     exit 1
  fi

  set +e
  kind get clusters | grep $CLUSTER_NAME > /dev/null 2>&1
  if [[ $? -eq 0 ]]; then
    echoerr "cluster $CLUSTER_NAME already created"
    exit 0
  fi
  set -e

  config_file="/tmp/kind.yml"
  cat <<EOF > $config_file
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
EOF
  for i in $(seq 1 $NUM_WORKERS); do
    echo -e "- role: worker" >> $config_file
  done
  kind create cluster --name $CLUSTER_NAME --config $config_file


  #Configure nodes
  declare -A hostMacs
  declare -A hostNames
  i=1
  for node in $(kubectl get node -o=jsonpath='{.items[*].metadata.name}'); do
    if [[ $node == *"worker"* ]]; then
      kubectl label node $node vpc.forge.nvidia.com/node=dpu
      docker exec $node ip netns add host
      docker exec $node ip link add dev p0 type veth peer name p0-peer
      docker exec $node ip link set p0-peer netns host
      docker exec $node ip netns exec host ip link set p0-peer up
      docker exec $node ip link set p0 up
      docker exec $node apt-get update
      docker exec $node apt-get install -y isc-dhcp-client
      docker exec $node apt-get install -y iputils-ping
      hostMacs[$i]=$(docker exec $node ip netns exec host ip -ts link show p0-peer | grep link | awk '{print $2}')
      hostNames[$i]=$node
    else
      kubectl label node $node vpc.forge.nvidia.com/node=control
      kubectl taint nodes $node node-role.kubernetes.io/master:NoSchedule-
    fi
    i=$((i+1))
  done

  # wait for cluster info
  while [[ -z $(kubectl cluster-info dump | grep cluster-cidr) ]]; do
    echo "waiting for k8s cluster readying"
    sleep 2
  done
  kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.4/cert-manager.yaml
  kind load docker-image $IMAGES --name $CLUSTER_NAME

  # configure and start dhcpd
  data_dir=$HOME/tmp/dhcpd-data
  mkdir -p "$data_dir"
  cp "$(dirname "$(readlink -f "$0")")/dhcpd.conf" "$data_dir"/
  echo host names and macs are "${hostNames[@]}" "${hostMacs[@]}"
  i=1
  for mac in "${hostMacs[@]}"; do
    oldMac="#HOST${i}_MAC#"
    sed -i "s/$oldMac/$mac/g" "$data_dir"/dhcpd.conf
    i=$((i+1))
  done
  i=1
  for name in "${hostNames[@]}"; do
    oldName="#HOST${i}_NAME#"
    sed -i "s/$oldName/$name/g" "$data_dir"/dhcpd.conf
    i=$((i+1))
  done
  cat "$data_dir"/dhcpd.conf
  docker run -ti --name $DHCPD_CONTAINER --network kind -v "$data_dir:/data" --init --detach networkboot/dhcpd eth0
}

function destroy {
  if [[ "$(docker ps -a)" == *"$DHCPD_NAME"* ]]; then
    docker rm -f $DHCPD_CONTAINER
  fi
  if [[ -z $CLUSTER_NAME ]]; then
    echoerr "cluster-name not provided"
    exit 1
  fi
  kind delete cluster --name $CLUSTER_NAME
}

while [[ $# -gt 0 ]]
 do
 key="$1"

  case $key in
    create)
      CLUSTER_NAME="$2"
      create
      exit 0
      ;;
    destroy)
      CLUSTER_NAME="$2"
      destroy
      exit 0
      ;;
    help)
      print_usage
      exit 0
      ;;
    *)    # unknown option
      echoerr "Unknown option $1"
      exit 1
      ;;
 esac
 done
