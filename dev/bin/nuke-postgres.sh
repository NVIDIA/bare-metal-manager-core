#!/usr/bin/env bash
###this script is intended to be used by developers against minikube to delete and recreate the forge database.
###It assumes that the API server is already down, usually accomplished by bringing down skaffold prior to running the script.

MAX_RETRY=10
i=0
while [[ $i -lt $MAX_RETRY ]]; do
  echo "Attempting to delete forge DB."
  kubectl exec -ti forge-pg-cluster-0  -n postgres -- /usr/bin/psql -U postgres -c "DROP DATABASE forge_system_carbide;"
  if [ $? -eq 0 ]; then
      echo "forge DB successfully deleted"
      break
  else
      echo "DB still has connections, waiting to retry."
      sleep 2
  fi

  i=$((i+1))
done

echo "Recreating forge db"
kubectl exec -ti forge-pg-cluster-0  -n postgres -- /usr/bin/psql -U postgres -c 'CREATE DATABASE forge_system_carbide with owner "forge-system.carbide";'


