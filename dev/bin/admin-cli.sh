#!/usr/bin/env bash

API_SERVER_HOST=$1
API_SERVER_PORT=$2
shift 2
CLI_ARGS="$@"

if [ "$FORGE_BOOTSTRAP_KIND" == "kube" ]; then
  # TODO install admin-cli somewhere
  # TODO mount repo in api container for data file access
  #kubectl exec --context minikube --namespace forge-system -it deploy/carbide-api -- bash -c "/opt/carbide/forge-admin-cli -c https://${API_SERVER_HOST}:${API_SERVER_PORT} $CLI_ARGS"
  echo ${REPO_ROOT}/target/debug/forge-admin-cli -c https://${API_SERVER_HOST}:${API_SERVER_PORT} ${CLI_ARGS}
  ${REPO_ROOT}/target/debug/forge-admin-cli -c https://${API_SERVER_HOST}:${API_SERVER_PORT} ${CLI_ARGS}
else
  # docker-compose case

  API_CONTAINER=$(docker ps | grep carbide-api | awk -F" " '{print $NF}')

  echo docker exec -ti ${API_CONTAINER} /opt/forge-admin-cli/debug/forge-admin-cli -c https://${API_SERVER_HOST}:${API_SERVER_PORT} --client-cert-path=/opt/forge/server_identity.pem --client-key-path=/opt/forge/server_identity.key $CLI_ARGS
  docker exec -ti ${API_CONTAINER} /opt/forge-admin-cli/debug/forge-admin-cli -c https://${API_SERVER_HOST}:${API_SERVER_PORT} --client-cert-path=/opt/forge/server_identity.pem --client-key-path=/opt/forge/server_identity.key $CLI_ARGS
fi

