# Kubernetes Development Workflow

## Base Forge Deployment 
The local development environment is based on the production kubernetes deployment.  For local development start by following [The forge deployment dev guide](https://gitlab-master.nvidia.com/nvmetal/forge-deployment/-/tree/master/dev) but *STOP* before `make forgedeploy`.  This is done in the forge-deployment repo

Alternatively, once the prerequisits are installed, the process can be done using the `dev/kube-init-dev.sh` script in the `forge-deployment` repo

At this point the kubernetes pods should look something like:
```
$ kubectl get pods -A
NAMESPACE        NAME                                      READY   STATUS    RESTARTS      AGE
cert-manager     cert-manager-8c6b9d496-9dj9h              1/1     Running   0             63m
cert-manager     cert-manager-cainjector-dbf668f8f-rj5xc   1/1     Running   0             63m
cert-manager     cert-manager-webhook-5dc88d9665-tckbl     1/1     Running   0             63m
kube-system      coredns-6d4b75cb6d-r62l5                  1/1     Running   0             63m
kube-system      etcd-minikube                             1/1     Running   0             64m
kube-system      kube-apiserver-minikube                   1/1     Running   0             64m
kube-system      kube-controller-manager-minikube          1/1     Running   0             64m
kube-system      kube-proxy-lv4t4                          1/1     Running   0             63m
kube-system      kube-scheduler-minikube                   1/1     Running   0             64m
kube-system      kubed-6fcd8b8786-t2cmz                    1/1     Running   0             63m
kube-system      storage-provisioner                       1/1     Running   1 (63m ago)   64m
metallb-system   metallb-controller-6d8dbb4576-cvhrz       1/1     Running   0             61m
metallb-system   metallb-speaker-g77bj                     1/1     Running   0             61m
postgres         forge-pg-cluster-0                        1/1     Running   0             60m
postgres         postgres-operator-674fbf8d97-wbph2        1/1     Running   0             61m
vault            vault-0                                   1/1     Running   0             62m
vault            vault-agent-injector-b4bcfc7c9-nrxgb      1/1     Running   0             62m
```

Note that there is no `forge-system` namespace yet.  if there is you have gone too far.

## Carbide Deployment
This is done in the carbide repo

### One Time Setup
The following need to be done once and only need to be repeated if changes are made to that affect them

#### Bootable Artifacts
Make sure that the [Bootable Artifacts](bootable_artifacts.md) have been installed or built<br>
TLDR: 
```
cd ${REPO_ROOT}/pxe
cargo make build-boot-artifacts-x86_64
cd ${REPO_ROOT}
sudo chown -R `whoami` pxe/static
```

#### Install Just
Just is used to run some scripts to make running the carbide cluster, monitor for source changes and updating the kubernetes pods as needed.
```
cargo install just
```

#### Build the necessary containers
```
just build-container-minikube
just runtime-container-minikube
```
once the containers are built, add the runtime container to minikube:
```
minikube cache add registry.minikube/runtime-container:latest
minikube cache reload
```

### Start Long Running Tasks
There are two tasks that run continuously while testing or iterating on chagnes.  The first one sets up a watch on different components in the `carbide` repo and notifies the second of changes.  The second one rebuilds and redeploys the changes to kubernetes<br>
Skaffold and just will stay running and pickup changes to code, containers or helm charts and rebuild and redeploy pods as necessary.  You may not want to leave them running while making multiple or large changes.

#### Setup watches
Start watching the repo for changes.  when a change occurs skaffold will be notified.  This is a continuous process and needs its own shell. <br>
This will also compile everything. 

```
$ just watch
mkdir -p .skaffold/cache && mkdir -p .skaffold/target && parallel --link  -j+0 --tty --tag cargo --color=always watch --why -C {1} -s \"${REPO_ROOT}/.skaffold/build {2}\" ::: api pxe dns dhcp ::: carbide-api carbide-pxe carbide-dns dhcp scout
[Running '/home/wminckler/code/carbide/.skaffold/build carbide-pxe']
[Running '/home/wminckler/code/carbide/.skaffold/build carbide-api']
[Running '/home/wminckler/code/carbide/.skaffold/build carbide-dns']
[Running '/home/wminckler/code/carbide/.skaffold/build dhcp']
info: syncing channel updates for '1.68.0-x86_64-unknown-linux-gnu'
[Running '/home/wminckler/code/carbide/.skaffold/build scout']

[...]

   Compiling rpc v0.0.1 (/carbide/rpc)
   Compiling dhcp v0.0.1 (/carbide/dhcp)
    Finished dev [unoptimized + debuginfo] target(s) in 32.24s
[Finished running. Exit status: 0]
    Finished dev [unoptimized + debuginfo] target(s) in 1m 14s
[Finished running. Exit status: 0]

```

Note that `just watch` starts multiple builds in parallel and you need to wait until its finished building before continuing (and when when you think its finished, wait another minute.)

#### Run Skaffold
Start Skaffold to respond to repo changes and re-deply carbide componenets. This is a continuous process and needs its own shell.  
```
$ skaffold dev
Generating tags...
 - registry.minikube/carbide-dns -> registry.minikube/carbide-dns:v0.0.1-1385-g98d3cb5b-dirty
 - registry.minikube/carbide-pxe -> registry.minikube/carbide-pxe:v0.0.1-1385-g98d3cb5b-dirty
 - registry.minikube/carbide-api -> registry.minikube/carbide-api:v0.0.1-1385-g98d3cb5b-dirty
 - registry.minikube/carbide-dhcp -> registry.minikube/carbide-dhcp:v0.0.1-1385-g98d3cb5b-dirty
Checking cache...
 - registry.minikube/carbide-dns: Found Locally
 - registry.minikube/carbide-pxe: Found Locally
 - registry.minikube/carbide-api: Found Locally
 - registry.minikube/carbide-dhcp: Found Locally
Tags used in deployment:
 - registry.minikube/carbide-dns -> registry.minikube/carbide-dns:397d80750c052b1f0fb0520da636e2de378f8dfa34a091974d7d3c2dd7d45693
 - registry.minikube/carbide-pxe -> registry.minikube/carbide-pxe:a1adde270cd0ebf3b07063a70fcdc483603b1836c60a522e4874cba04478d26e
 - registry.minikube/carbide-api -> registry.minikube/carbide-api:ef8cbd98ce72d72c7c486890af4c100648fae5bda2c73192c3ee339fa2933280
 - registry.minikube/carbide-dhcp -> registry.minikube/carbide-dhcp:76f60e4a9606774a515721161ab30c65b3aefb523186a4d9977a1cc62b883db2
Starting deploy...
Helm release carbide-dns not installed. Installing...
Hang tight while we grab the latest from your chart repositories...
...Successfully got an update from the "nvidia" chart repository
...Successfully got an update from the "nvidia-stg" chart repository
...Successfully got an update from the "appscode" chart repository
...Successfully got an update from the "bitnami" chart repository
Update Complete. ⎈Happy Helming!⎈

[...]

[carbide-api] 2023-04-12T04:16:01.540837Z  INFO run: carbide::ipmi: api/src/ipmi.rs:505: Starting IPMI handler.    
[carbide-dns]  2023-04-12T04:15:46.418Z INFO  carbide_dns::dns > Connecting to carbide-api at "http://carbide-api.forge-system.svc.cluster.local:1079"
[carbide-dns]  2023-04-12T04:15:46.418Z INFO  carbide_dns::dns > Started DNS server on [::]:1053
Watching for changes...

```

Note that once you see "Watching for changes....", skaffold will no longer tail logs


## Seeding DB

seed the database with some test data:

```
cargo make bootstrap-forge-kube
```

This will create

1. a new `Domain`
2. a new `NetworkSegment`
3. a new `Vpc`
4. a new `DPU`
5. a new `Host`

Note that the DPU and the Host are related and the VM created below is host half of the pair.

## Sanity check

The `bootstrap-forge-kube` command above should succeed. Now Carbide has
some data. Query carbide-api:

```
$ ./target/debug/forge-admin-cli -c https://192.168.252.75:1079/ network-segment show --all
+--------------------------------------+------+-----------------------------+-------+-------------+------+---------------+---------------------------------------------+----------------------+
| Id                                   | Name | Created                     | State | Sub Domain  | MTU  | Prefixes      | Circuit Ids                                 | Version              |
+--------------------------------------+------+-----------------------------+-------+-------------+------+---------------+---------------------------------------------+----------------------+
| 1f32f763-4bf4-4401-a226-5c0cc4a1c040 | test | 2023-04-12T04:46:23.596033Z | Ready | forge.local | 1490 | 172.20.0.0/24 | 08a01d3a-7f55-405f-b082-e90fc947eac0Circuit | V1-T1681274783596196 |
+--------------------------------------+------+-----------------------------+-------+-------------+------+---------------+---------------------------------------------+----------------------+

```

It should display a table with one network segment


## Creating the Host VM
There are 2 VM config files, one is in the `forge-deployment` repo (environments/local/managedhost.xml) and one in the `carbide` repo (dev/libvirt_host.xml).  The process is the same for both and they create the same machine (so do not run both at once).

```
virsh define dev/libvirt.xml
virsh start ManagedHost
vrrsh console ManagedHost
```

login using `root` and `password`

### Stop and remove the Host VM
use `destroy` to turn off the vm and `undefine` to remove it from libvirt

```
virsh destroy ManagedHost
virsh undefine ManagedHost --nvram
```

