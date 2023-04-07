# forge-admin-cli access on a Forge cluster

The following steps can be used on a control-plane node of a Forge cluster
to gain access to `forge-admin_cli`:

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
/opt/carbide/forge-admin-cli -c https://127.0.0.1:1079 machine show --all
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
/opt/carbide/forge-admin-cli -c https://10.104.18.37:1079 machine show --all
```

**Note:** Once forge site controller migrates to using TLS, you might need
to use `https:` as schema