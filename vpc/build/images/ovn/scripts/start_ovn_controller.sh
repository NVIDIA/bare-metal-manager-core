#!/usr/bin/env bash
#set -euo pipefail

BR_TRANSPORT=${DPU_BR_TRANSPORT:-br-transport}
/usr/share/openvswitch/scripts/ovs-ctl --system-id=random start

# TODO, create transport bridge
IP=$(ip addr show eth0 | awk '$1 == "inet" {print $2}' | cut -f1 -d/)
GW=$(ip route show default | awk '{print $3}')
echo "IP=$IP, GW=$GW"
echo "ip addr delete dev eth0 $IP/16"
ip addr delete dev eth0 "$IP/16"
echo "ovs-vsctl --may-exist add-br $BR_TRANSPORT"
ovs-vsctl --may-exist add-br "$BR_TRANSPORT"
echo "ovs-vsctl --may-exist add-port $BR_TRANSPORT eth0"
ovs-vsctl --may-exist add-port "$BR_TRANSPORT" eth0
echo "ip link set $BR_TRANSPORT up"
ip link set "$BR_TRANSPORT" up
echo "ip addr add dev $BR_TRANSPORT $IP/16"
ip addr add dev "$BR_TRANSPORT" "$IP/16"
echo "ip route add default via $GW"
ip route add default via "$GW"

##### TODO agent dynamic
ovs-vsctl set open_vswitch .  \
  external_ids:ovn-remote="tcp:$OVN_CENTRAL_SERVICE_HOST:$OVN_CENTRAL_SERVICE_PORT_SOUTH" \
  external_ids:ovn-encap-ip="$(ip addr show "$BR_TRANSPORT" | awk '$1 == "inet" {print $2}' | cut -f1 -d/)" \
  external_ids:ovn-encap-type=geneve \
  external_ids:system-id="$(hostname)" \
  external_ids:ovn-bridge-mappings=provider:"$BR_TRANSPORT"

/usr/share/ovn/scripts/ovn-ctl start_controller
ovs-vsctl add-port br-int p0 -- \
    set Interface p0 external_ids:iface-id="$(hostname)-p0"

while true; do
  sleep 30
done
