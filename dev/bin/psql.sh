#!/usr/bin/env bash

SQL_QUERY=$1

if [ "$FORGE_BOOTSTRAP_KIND" == "kube" ]; then
  CARBIDE_API_POD=$(kubectl get pod --context minikube --namespace forge-system -l='carbide_api_pod=yes' -o json | jq -r '.items[0].metadata.name')
  echo "running psql inside pod ${CARBIDE_API_POD}"
  kubectl exec --context minikube --namespace forge-system -it ${CARBIDE_API_POD} -- \
    bash -c 'psql postgres://${DATASTORE_USER}:${DATASTORE_PASSWORD}@${DATASTORE_HOST}:${DATASTORE_PORT}/${DATASTORE_NAME} -c '"${SQL_QUERY}"
else
  psql -t -c "${SQL_QUERY}"
fi

