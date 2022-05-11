#!/usr/bin/env bash

set -euo pipefail

/usr/share/ovn/scripts/ovn-ctl start_northd
if [[ "yes" == ${OVN_SSL_ENABLE} ]]; then
  /usr/bin/ovn-sbctl set-ssl ${OVN_CERT_PATH}/tls.key ${OVN_CERT_PATH}/tls.crt ${OVN_CERT_PATH}/ca.crt
  /usr/bin/ovn-sbctl set-connection pssl:6642
  /usr/bin/ovn-nbctl set-ssl ${OVN_CERT_PATH}/tls.key ${OVN_CERT_PATH}/tls.crt ${OVN_CERT_PATH}/ca.crt
  /usr/bin/ovn-nbctl set-connection pssl:6641
else
  /usr/bin/ovn-sbctl set-connection ptcp:6642
  /usr/bin/ovn-nbctl set-connection ptcp:6641
fi

trap exit SIGINT SIGTERM SIGQUIT
echo "Started OVN"
while true; do
    sleep 30
    if [[ "yes" == ${OVN_SSL_ENABLE} ]]; then
      # Handle rotating cert.
      /usr/bin/ovn-sbctl set-ssl ${OVN_CERT_PATH}/tls.key ${OVN_CERT_PATH}/tls.crt ${OVN_CERT_PATH}/ca.crt
      /usr/bin/ovn-nbctl set-ssl ${OVN_CERT_PATH}/tls.key ${OVN_CERT_PATH}/tls.crt ${OVN_CERT_PATH}/ca.crt
    fi
    if ! /usr/share/ovn/scripts/ovn-ctl status_northd > /dev/null 2>&1; then
      echo "OVN is not running properly restarting"
      /usr/share/ovn/scripts/ovn-ctl restart_northd
    fi
done
