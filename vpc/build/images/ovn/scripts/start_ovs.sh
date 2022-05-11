#!/usr/bin/env bash
SYSTEM_ID=$(hostname)

/usr/share/openvswitch/scripts/ovs-ctl --system-id="$SYSTEM_ID" start

trap exit SIGINT SIGTERM SIGQUIT

while true; do
  sleep 30
  /usr/share/openvswitch/scripts/ovs-ctl status > /dev/null 2>&1
  if ! /usr/share/openvswitch/scripts/ovs-ctl status > /dev/null 2>&1; then
    echo "openvswitch is in bad state, restarting"
    usr/share/openvswitch/scripts/ovs-ctl restart --system-id="$SYSTEM_ID"
  fi
done

