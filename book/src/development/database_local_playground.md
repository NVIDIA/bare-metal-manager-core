# Local Playground with minikube
This is intended for people who want to set up a local database environment (separate from the full *Forge* environment), for the purpose of playing around with the database cluster, its components (`postgres-operator`, *Patroni*, `postgres_exporter`, etc), and testing out various changes to it. This is also a place where you can, of course, apply the `carbide_schema.sql` file to also set up a an actual database for testing as well.

This document is broken up into two "sections":
- **Environment Creation**, which are 7 steps to a great cluster.
- **Environment Validation**, which are just various things you can do to look around and see that everything is good.

## Environment Creation

Note: The installation of CRDs doesn't need to be in the exact order as described in this doc.

### 1. Install minikube + create a cluster.

This will download the latest `.deb`, install it, and start up a new *minikube* cluster with the profile name of `local-forge-db`. Calling it `local-forge-db` is optional, but if you plan on having (or already have) multiple *minikube* profiles, it's nice to have a unique name.

And, once you're done, make sure to `minikube profile local-forge-db`, which will also ensure your `kubectl config current-context` is set appropriately. I think this happens as part of `start` anyway, but it seems like a nice habit to be in.

```
$ curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube_latest_amd64.deb
$ sudo dpkg -i minikube_latest_amd64.deb
$ minikube start -p local-forge-db
$ minikube profile local-forge-db
```

**And if you're on a Mac (with Apple Silicon), you'll need to also run this:**
```
$ minikube ssh "sudo apt-get update && sudo apt-get -y install qemu-user-static"
```

### 2. Install CRDs for external-secrets

This is used by the `postgres-operator` for managing the passwords for the *Postgres* superuser and replication user(s). You don't have to generate secrets -- the `postgres-operator` takes care of that for you.

```
$ helm repo add external-secrets https://charts.external-secrets.io
$ helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace --set installCRDs=true
```

### 3. Install CRD for local-path provisioner

This is the `storageClass` used by `postgres-operator`.

```
kubectl apply -f https://raw.githubusercontent.com/rancher/local-path-provisioner/master/deploy/local-path-storage.yaml
```

So it's better to just install the `local-path` CRD.

### 4. Install CRDs for prometheus-operator

For getting at the pod-level metrics for *Postgres* and *Patroni*. This is as
simple as following the guide from their [getting started](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/user-guides/getting-started.md):

```
$ LATEST=$(curl -s https://api.github.com/repos/prometheus-operator/prometheus-operator/releases/latest | jq -cr .tag_name)
$ curl -sL https://github.com/prometheus-operator/prometheus-operator/releases/download/${LATEST}/bundle.yaml | kubectl create -f -
```

### 5. Install CRDs for postgres-operator

And now install the CRDs for `postgres-operator` itself!

```
$ CRD_BASE="https://raw.githubusercontent.com/zalando/postgres-operator/master/charts/postgres-operator/crds"
$ kubectl apply -f $CRD_BASE/operatorconfigurations.yaml
$ kubectl apply -f $CRD_BASE/postgresqls.yaml
$ kubectl apply -f $CRD_BASE/postgresteams.yaml
```

Check out the [CRDs](https://github.com/zalando/postgres-operator/tree/master/charts/postgres-operator/crds) for more details.

### 6. Apply the postgres-operator base resources

Now it's time to apply the base `postgres-operator` resources from `nvmetal/forged`:

```
$ cd ~/src/gitlab-master.nvidia.com/nvmetal/forged/bases/postgres-operator
$ just build . | kubectl apply -n postgres -f -
```

### 7. Apply the forge-pg-cluster component resources

This is the last of the resources -- you made it!

```
$ cd ~/src/gitlab-master.nvidia.com/nvmetal/forged/components/forge-pg-cluster
$ just build . | kubectl apply -n postgres -f -
```

## Environment Validation

Now that you've applied all of the resources, lets poke around and make sure things look good!

### Pod validation

You should see something like below when you look at the available pods in the cluster, **BUT**, when you **FIRST** apply the `forge-pg-cluster` component resources (the last step from above), it may take a minute or so for:
- The `postgres-operator` pod to come up.
- The `forge-pg-cluster` StatefulSet pods to serially come up. If you keep running `kubectl get pods -A` you can follow along.

```
$ kubectl get pods -A
NAMESPACE            NAME                                                READY   STATUS    RESTARTS   AGE
default              prometheus-operator-7d5c68dc4-twwdl                 1/1     Running   0          26m
external-secrets     external-secrets-7b54f9cb88-ms9cq                   1/1     Running   0          27m
external-secrets     external-secrets-cert-controller-587687d696-xc8q7   1/1     Running   0          27m
external-secrets     external-secrets-webhook-cbd54d899-zxj4d            1/1     Running   0          27m
kube-system          coredns-5dd5756b68-zhzbh                            1/1     Running   0          28m
kube-system          etcd-local-forge-db2                                1/1     Running   0          28m
kube-system          kube-apiserver-local-forge-db2                      1/1     Running   0          28m
kube-system          kube-controller-manager-local-forge-db2             1/1     Running   0          28m
kube-system          kube-proxy-2jvgj                                    1/1     Running   0          28m
kube-system          kube-scheduler-local-forge-db2                      1/1     Running   0          28m
kube-system          storage-provisioner                                 1/1     Running   0          28m
local-path-storage   local-path-provisioner-5d854bc5c4-dmwkt             1/1     Running   0          26m
postgres             forge-pg-cluster-0                                  2/2     Running   0          26m
postgres             forge-pg-cluster-1                                  2/2     Running   0          25m
postgres             forge-pg-cluster-2                                  2/2     Running   0          25m
postgres             postgres-operator-95d66d878-npftf                   1/1     Running   0          26m
```

### Database validation

Now lets login to a database node and check it out! The `forge-pg-cluster-0` node is going to always be the initial leader (it's the first pod up, so, by design, will be the leader):

```
$ kubectl exec -ti forge-pg-cluster-0 -n postgres -- bash
Defaulted container "postgres" out of: postgres, postgres-exporter

 ____        _ _
/ ___| _ __ (_) | ___
\___ \| '_ \| | |/ _ \
 ___) | |_) | | | (_) |
|____/| .__/|_|_|\___/
      |_|

This container is managed by runit, when stopping/starting services use sv

Examples:

sv stop cron
sv restart patroni

Current status: (sv status /etc/service/*)

run: /etc/service/patroni: (pid 32) 1708s
run: /etc/service/pgqd: (pid 33) 1708s
```

We're in! Lets check out the database topology to make sure all nodes are showing up:
```
root@forge-pg-cluster-0:/home/postgres# patronictl topology
+ Cluster: forge-pg-cluster ---------+--------------+---------+----+-----------+
| Member               | Host        | Role         | State   | TL | Lag in MB |
+----------------------+-------------+--------------+---------+----+-----------+
| forge-pg-cluster-0   | 10.244.0.10 | Leader       | running |  1 |           |
| + forge-pg-cluster-1 | 10.244.0.12 | Replica      | running |  1 |         0 |
| + forge-pg-cluster-2 | 10.244.0.14 | Sync Standby | running |  1 |         0 |
+----------------------+-------------+--------------+---------+----+-----------+
```

Looks good! In our current setup, one node will be a "synchronous standby" (which is currently `forge-pg-cluster-2`), and the other node will be an async replica (currently `forge-pg-cluster-1`).

### Tunnel to access the Service VIP from your workstation

Chances are you will want to be able to connect to your database cluster from your workstation, so you can use tools like `psql` and others, without needing to be *within* the cluster. In this case, you're going to need to do a few things:
1. Set `enableMasterLoadBalancer` (step 1 below).
2. Kick off `minikube tunnel` (step 2 below).

#### 1. Request an "external IP" with `enableMasterLoadBalancer`.

The `postgres-operator` creates a couple of VIPs:
- `forge-pg-cluster`: This is a service that points to the leader (writes).
- `forge-pg-cluster-repli`: This is a service that balances between the replicas (reads).

```
$ kubectl get service -n postgres
NAME                      TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)    AGE
forge-pg-cluster          ClusterIP   10.104.96.77    <none>        5432/TCP   36m
forge-pg-cluster-config   ClusterIP   None            <none>        <none>     35m
```

...but the problem is, they don't have external IPs:

```
$ kubectl get service -n postgres
NAME                      TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
forge-pg-cluster          ClusterIP      10.104.96.77    <none>        5432/TCP         45m
```

Luckily, `postgres-operator` provides an `enableMasterLoadBalancer` option to change the service type to `LoadBalancer`, after which you can then run `minikube tunnel` to expose it.

Edit the resource:
```
$ kubectl edit postgresql forge-pg-cluster -n postgres
```

Right under `spec:`, you simply add:
```
enableMasterLoadBalancer: true
```

And it should be happy:
```
postgresql.acid.zalan.do/forge-pg-cluster edited
```

And **NOW**, since we enabled a load balancer for the *master*, you should see the "master" VIP has a `<pending>` IP:
```
$ kubectl get service -n postgres
NAME                      TYPE           CLUSTER-IP      EXTERNAL-IP   PORT(S)          AGE
forge-pg-cluster          LoadBalancer   10.104.96.77    <pending>     5432:32243/TCP   45m
```

Guess what's next? Yup, `minikube tunnel`.

#### 2. Expose the external IP with minikube tunnel.

Now that external IPs are being requested, `minikube tunnel` is your friend (which you'll want to keep open in the background with `&` or `nohup`, or just leave a terminal window open).

Just make sure you're in the profile you want to expose a tunnel for, and go!

```
$ minikube profile local-forge-db
$ minikube tunnel
[sudo] password for chet:             
Status:	
	machine: local-forge-db
	pid: 875893
	route: 10.96.0.0/12 -> 192.168.58.2
	minikube: Running
	services: []
    errors: 
		minikube: no errors
		router: conflicting route: 10.96.0.0/12 via 192.168.49.2 dev br-8b7abf4549ab 
		loadbalancer emulator: no errors
```

And now you should have an external IP!
```
$ kubectl get service -n postgres
NAME                      TYPE           CLUSTER-IP      EXTERNAL-IP    PORT(S)          AGE
forge-pg-cluster          LoadBalancer   10.104.96.77    10.104.96.77   5432:32243/TCP   46m
```

### Import the Forge Carbide schema

Now that you have direct access to your leader VIP (thanks to `enableMasterLoadBalancer` and `minikube tunnel` above), you will now be able to run `psql` commands directly from your workstation, including using it to apply `carbide_schema.sql`.
  
### 1. First, you'll need the `postgres` user password:
```
$ kubectl exec -ti forge-pg-cluster-0 -n postgres -- cat postgres.yml | grep -A1 "superuser" | grep password:
      password: Rfyydsfadsasd2OGosIxr0qeqweqweasdlksudhalquewghqwleukpooosaodsdkjl
```
  
### 2. Now try running psql

```
$ psql -h 10.104.96.77 -U postgres

forge_system_carbide=# \l
                                                List of databases
         Name         |           Owner            | Encoding |   Collate   |    Ctype    |   Access privileges   
----------------------+----------------------------+----------+-------------+-------------+-----------------------
 elektra              | elektra-site-agent.elektra | UTF8     | en_US.utf-8 | en_US.utf-8 | 
 forge_system_carbide | forge-system.carbide       | UTF8     | en_US.utf-8 | en_US.utf-8 | 
 postgres             | postgres                   | UTF8     | en_US.utf-8 | en_US.utf-8 | 
 template0            | postgres                   | UTF8     | en_US.utf-8 | en_US.utf-8 | =c/postgres          +
                      |                            |          |             |             | postgres=CTc/postgres
 template1            | postgres                   | UTF8     | en_US.utf-8 | en_US.utf-8 | =c/postgres          +
                      |                            |          |             |             | postgres=CTc/postgres
(5 rows)
```

You will notice the `forge_system_carbide` database already exists! This is because it's a part of provisioning that comes with our `forge-pg-cluster` resource. **THAT SAID**, there's nothing in it:

```
forge_system_carbide=# \c forge_system_carbide
psql (14.10 (Ubuntu 14.10-0ubuntu0.22.04.1), server 15.2 (Ubuntu 15.2-1.pgdg22.04+1))
WARNING: psql major version 14, server major version 15.
         Some psql features might not work.
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "forge_system_carbide" as user "postgres".
forge_system_carbide=# \d
                 List of relations
 Schema |          Name           | Type |  Owner   
--------+-------------------------+------+----------
 public | pg_stat_kcache          | view | postgres
 public | pg_stat_kcache_detail   | view | postgres
 public | pg_stat_statements      | view | postgres
 public | pg_stat_statements_info | view | postgres
(4 rows)
```

So lets import the schema!

```
$ cd ~/src/gitlab-master.nvidia.com/nvmetal/carbide/dev/
direnv: loading ~/src/gitlab-master.nvidia.com/nvmetal/carbide/.envrc
direnv: export +DATABASE_URL +REPO_ROOT +RUSTC_WRAPPER +TESTDB_HOST +TESTDB_PASSWORD +TESTDB_USER
$ psql -h 10.104.96.77 -U postgres forge_system_carbide < carbide_schema.sql
```

And now verify!

```
chet@groundhog:dev $ psql -h 10.104.96.77 -U postgres forge_system_carbide
Password for user postgres: 
psql (14.10 (Ubuntu 14.10-0ubuntu0.22.04.1), server 15.2 (Ubuntu 15.2-1.pgdg22.04+1))
WARNING: psql major version 14, server major version 15.
         Some psql features might not work.
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

forge_system_carbide=# \d
                                List of relations
 Schema |                 Name                 |   Type   |        Owner         
--------+--------------------------------------+----------+----------------------
 public | _sqlx_migrations                     | table    | forge-system.carbide
 public | bmc_machine                          | table    | forge-system.carbide
 public | bmc_machine_controller_lock          | table    | forge-system.carbide
 public | dhcp_entries                         | table    | forge-system.carbide
 public | dns_records                          | view     | forge-system.carbide
 public | dns_records_adm_combined             | view     | forge-system.carbide
 public | dns_records_bmc_dpu_id               | view     | forge-system.carbide
 public | dns_records_bmc_host_id              | view     | forge-system.carbide
 public | dns_records_shortname_combined       | view     | forge-system.carbide
 public | domains                              | table    | forge-system.carbide
 public | dpu_agent_upgrade_policy             | table    | forge-system.carbide
 public | dpu_machines                         | view     | forge-system.carbide

```

Looks good!
