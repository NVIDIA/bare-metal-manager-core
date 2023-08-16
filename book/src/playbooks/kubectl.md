# kubectl for Forge - cheat sheet

This page lists `kubectl` commands that can be executed on Forge clusters for maintenance tasks

## Log viewing

### Tail forge API server (carbide-api) logs

```
kubectl logs -n forge-system deploy/carbide-api --all-containers -f
```

### Tee logs (for offline viewing)

```
kubectl logs -n forge-system deploy/carbide-api --all-containers -f | tee -a /tmp/myuserlogs.txt
```

## carbide-api shell access

```
kubectl exec -it -n forge-system deploy/carbide-api -- /bin/sh
```

## Database access

```
kubectl exec -ti forge-pg-cluster-0 -n postgres -- /usr/bin/psql -U postgres forge_system_carbide
```
