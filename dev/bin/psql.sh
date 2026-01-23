#!/usr/bin/env bash

SQL_QUERY=$1

if [ "$FORGE_BOOTSTRAP_KIND" == "kube" ]; then
  kubectl exec --context minikube --namespace forge-system -it deploy/carbide-api -- bash -c 'psql -P pager=off -t postgres://${DATASTORE_USER}:${DATASTORE_PASSWORD}@${DATASTORE_HOST}:${DATASTORE_PORT}/${DATASTORE_NAME} -c '"\"${SQL_QUERY}\""
else
  psql -t --quiet -P pager=off -c "${SQL_QUERY}"
fi

