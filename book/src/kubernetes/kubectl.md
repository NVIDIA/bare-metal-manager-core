This page lists `kubectl` commands that can be executed on Forge clusters for maintainence tasks

## Log viewing

### Tail forge API server (carbide-api) logs

```
kubectl logs -n forge-system -l app.kubernetes.io/component=carbide-api --all-containers -f
```

### Tail logs for all all site controller components (incl PXE, DHCP)

```
kubectl logs -n forge-system -l app.kubernetes.io/instance=carbide --all-containers -f
```

### Tee logs (for offline viewing)

```
kubectl logs -n forge-system -l app.kubernetes.io/component=carbide-api --all-containers -f | tee -a /tmp/myuserlogs.txt
```

## Database access

```
kubectl exec -ti forge-pg-cluster-0 -n postgres -- /usr/bin/psql -U postgres forge_system_carbide
```

## forge-admin-cli access

1. Enter the api-server POD, which also contains copy of `forge-admin-cli`:
```
kubectl exec -ti deploy/carbide-api -n forge-system -- /bin/bash
```

2. Move to forge-admin-cli directory (optional)
```
cd /opt/carbide/
```

3. Utilize the admin-cli
```
/opt/carbide/forge-admin-cli -c http://127.0.0.1:1079 machine show --all
```

Note that you can either use a loopback address (`127.0.0.1`) inside the POD,
or use the cluster-ip of the service, which can be obtained by

```
kubectl get services -n forge-system
```

Output:
```
carbide-api    NodePort    10.104.18.37     <none>        1079:1079/TCP       28d
```

Therefore also the following invocation is possible:
```
/opt/carbide/forge-admin-cli -c http://10.104.18.37:1079 machine show --all
```

**Note:** Once forge site controller migrates to using TLS, you might need
to use `https:` as schema
