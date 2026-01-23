#!/usr/bin/env bash
if [ $# -lt 2 ]
then
    echo "Usage: $0 <control-plane-node> <dpu machine id> [<ssh-args>...]"
    exit 1
fi

set -e

rawout=$(echo y | TERM=xterm ssh -tt $1 sudo kubectl exec -qti deploy/carbide-api -n forge-system -- bash -c "'"'/opt/carbide/forge-admin-cli -c https://${CARBIDE_API_SERVICE_HOST}:${CARBIDE_API_SERVICE_PORT} machine show --machine='$2' 2> /dev/null  && sleep 1 && /opt/carbide/forge-admin-cli -f json -c https://${CARBIDE_API_SERVICE_HOST}:${CARBIDE_API_SERVICE_PORT} machine dpu-ssh-credentials --query='$2' 2> /dev/null '"'" 2> /dev/null | col -b)
#echo ---${rawout}---

address=$(echo $rawout | sed -e 's/.*Addresses : \([0-9.]*\).*/\1/g')
user=$(echo $rawout | sed -e 's/.*"username" *: *"\([^ ]*\)".*/\1/g')
export SSHPASS=$(echo $rawout | sed -e 's/.*"password" *: *"\([^ ]*\)".*/\1/g')

shift 2
sshpass -e ssh $user@$address "$@"
#echo address: $address
#echo user: $user
#echo pass: $SSHPASS
