This document describes a development environment on Ubuntu 20.04. 

#Prerequisites
[KinD, Kubectl](https://kubernetes.io/docs/tasks/tools/),
[protobuf](https://grpc.io/docs/protoc-installation/):
Please see .gitlab-ci.yaml for installation commands.

[golang 1.16](https://go.dev/doc/install)

[docker ce](https://docs.docker.com/engine/install/ubuntu/)

# Build
Binaries may be built either in a container or in local environment.

To prepare build in local environment
```bash
export DOCKERIZED=false
```

To prepare build in docker
```bash
export DOCKERIZED=true
mkdir -p .go/pkg
mkdir -p .go/cache
```

## Binaries
```bash
make
```
## Manifests
```bash
make manifests
```
## Unit test
```bash
make test
```
## Docker containers
```bash
make docker-build
```
## Push docker containers to quay.io
The hydrazine container is quay.io/nvidia/nvmetal-hydrazine
Assume you have already logged into quay.io
```bash
make docker-push
```

# Development Environment
```bash
./ci/kind/kind-setup.sh create hydrazine
```
You should now see a KinD K8s cluster created.
## Deploy hydrazine
```bash
kubectl apply -f config/hydrazine.yaml
```
You should now see hydrazine being deployed in the K8s cluster.
```bash
kubectl get pods -n hydrazine-system
NAME                                                READY   STATUS    RESTARTS   AGE
hydrazine-controller-manager-6dd76f49df-4m42k       2/2     Running   0          41h
hydrazine-grpc-server-654567c49c-qtp8f              1/1     Running   0          41h
```
## Re-deploy hydrazine
You have made some changes to hydrazine controller, and now you want to test those changes in the deployment.
```bash
make docker-build
kind load docker-image quay.io/nvidia/nvmetal-hydrazine --name hydrazine
kubeclt delete pod hydrazine-controller-manager-REMINDER -n hydrazine-system
```

## Test network fabric implementation
See [cumulus.md](./cumulus.md) to ensure cumulus devices are reachable from the K8s cluster.
Create networkFabric Edge, TOR, Hosts
```bash
kubectl apply -f config/sample/demo/fabric/fabric.yaml
```
You should see TOR device is connected.
```
TODO 
```
Create ResourceGroup and its ManagedResources using fabric backend.
```bash
kubectl apply -f config/sample/demo/fabric/resource.yaml
```
You should see ManagedResources (hosts) are connected by TOR.
```bash
TODO
```
## Test OVN/OVS implementation
Deploy agents on worker node (emulating DPUs), 
```bash
kubectl apply -f config/agent.yaml
```
Create a ResourceGroup using software/ovn backend.
```bash
kubectl apply -f config/sample/demo/ovn/resource.yaml
```
This should generate an ovn-central instance.
```bash
kubectl get pods -n hydrazine-system
NAME                                                READY   STATUS    RESTARTS   AGE
hydrazine-agent-59dd6                               2/2     Running   0          42h
hydrazine-agent-7c45b                               2/2     Running   0          42h
hydrazine-controller-manager-6dd76f49df-4m42k       2/2     Running   0          42h
hydrazine-grpc-server-654567c49c-qtp8f              1/1     Running   0          42h
ovn-central-test-resourcegroup-1-65c77fd588-qksnw   1/1     Running   0          24h
```