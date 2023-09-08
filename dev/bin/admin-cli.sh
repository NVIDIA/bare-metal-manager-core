#!/usr/bin/env bash

CLI_ARGS="$@"

if [ "$FORGE_BOOTSTRAP_KIND" == "kube" ]; then
  kubectl exec --context minikube --namespace forge-system -it deploy/carbide-api -- bash -c \
      "/opt/carbide/forge-admin-cli --forge-root-ca-path=/var/run/secrets/spiffe.io/ca.crt --client-cert-path=/var/run/secrets/spiffe.io/tls.crt --client-key-path=/var/run/secrets/spiffe.io/tls.key -c https://carbide-api.forge-system.svc.cluster.local:\${CARBIDE_API_SERVICE_PORT} $CLI_ARGS"
else
  # docker-compose case

  API_CONTAINER=$(docker ps | grep carbide-api | awk -F" " '{print $NF}')

  echo docker exec -ti ${API_CONTAINER} /opt/forge-admin-cli/debug/forge-admin-cli -c https://${API_SERVER_HOST}:${API_SERVER_PORT} --client-cert-path=/opt/forge/server_identity.pem --client-key-path=/opt/forge/server_identity.key $CLI_ARGS
  docker exec -ti ${API_CONTAINER} /opt/forge-admin-cli/debug/forge-admin-cli -c https://${API_SERVER_HOST}:${API_SERVER_PORT} --client-cert-path=/opt/forge/server_identity.pem --client-key-path=/opt/forge/server_identity.key $CLI_ARGS
fi

