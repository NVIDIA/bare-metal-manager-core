# Forge Site Bootstrap / Forge Install

There are two distinct workflows to bootstrap a new site and install
Forge.

If the site is a Fleet Command site, then follow the directions [for
installing under FleetCommand](#fleet-command-environment)

If the site is not a FleetCommand site, then follow the directions [for installing using Helm](#helm)

## Fleet Command environment

For Fleet Command base Forge installs, look at [SRE Workflow doc for
Forge](https://docs.google.com/document/d/1tuETD9chsOO03nYaQSYPNPLfYuA7_cl15uAxhAJ0a5g/edit#heading=h.ajik68ox788i)


## HELM
Before proceeding, make sure you have completed the instructions for [Setting up Helm](../kubernetes/helm.md)

Next, clone the [forge-deployment git repo](https://gitlab-master.nvidia.com/nvmetal/forge-deployment)

**NOTE**
If the environment _requires_ changes, edit the YAML file in the corresponding `environment/$environment/<file>.yaml`, e.g., In the `dev1` environment, there is one Kubernetes host. The default `replicaCount` of 3 for the `vault` chart causes the install to hang and eventually time out. `vault` will fail to start if there is less than `replicaCount` available. 
 
Changing `environment/$environment/fleetcommand/vault.yaml` overriding the vault-specific configuration to `replicaCount: 1` allows `vault` to
install and start successfully.

### Kubed
---
Install appscode/kubed for synchronizing `imagepullsecret` to current/future namespaces

For `kubelet` to pull containers from container registries `nvcr.io` and
`stg.nvcr.io`, `imagepullsecret` must first exist in the `default` namespace.
`appscode/kubed` handles synchronizing the Kubernetes `secret` from the
default namespace to new/existing namespaces.

TODO: appscode/kubed mirror locally

```
helm repo add appscode https://charts.appscode.com/stable/

helm install kubed appscode/kubed \
 --version v0.12.0 \
 --namespace kube-system
```

Once installed in the cluster, add an `annotation` to the `secret` named `imagepullsecret`:

```
...
metadata:
  annotations:
  ...
    kubed.appscode.com/sync: "true"
```

### cert-manager
---
Forge has a dependency on `Vault`, `cert-manager`, and
`cert-manager-csi-driver-spiffe`.

Carbide pods will fail to start without these components installed and configured correctly.

```
helm upgrade -i -n cert-manager cert-manager --set forge.bootstrap.enabled=true --values values.yaml --values environments/$environment/fleetcommand/cert-manager.yaml --create-namespace --atomic --debug .
```

Once the install completes, you need manually approve two `CertificateRequests`:

```
kubectl cert-manager approve -n vault $(kubectl get cr -n vault -ojsonpath='{.items[0].metadata.name}')

kubectl cert-manager approve -n vault $(kubectl get cr -n vault -ojsonpath='{.items[1].metadata.name}')
```

### Vault
---

```
helm upgrade -i -n vault vault --set forge.bootstrap.enabled=true --values values.yaml   --values environments/$environment/fleetcommand/vault.yaml  --debug  --atomic .
```

### Postgres-Operator
---
```
helm upgrade -i -n postgres postgres-operator --values values.yaml  --values environments/$environment/fleetcommand/postgres-operator.yaml --create-namespace --debug .
```

### ForgeDB
---

This `chart` creates the forge database, sets up the user/pass, and the Kubernetes `service` that carbide components will use.

```
helm upgrade -i -n postgres forgedb --values values.yaml --set "ForgeDataBase.install=true" --values environments/dev2/fleetcommand/forgedb.yaml  --dry-run --debug .
```

### carbide
---

```
 helm upgrade -i -n forge-system carbide --values values.yaml --values environments/$environment/fleetcommand/forge.yaml --debug  .
 ```

#### vpc
---
VPC has three `charts` that are installed and upgraged separately.

1. vpc-crds - CRD definitions for VPC.  These are maintained in a separate package to allow upgrades
without impacting VPC itself
2. vpc - The actual softare VPC.  
3. vpc-site - Site specific VPC resources such as `administration-resource-group` and  `configurationresourcepool`

```
helm upgrade -i -n forge-system vpc --values values.yaml  --values environments/$environment/fleetcommand/vpc-crds.yaml --debug .

helm upgrade -i -n forge-system vpc --values values.yaml  --values environments/$environment/fleetcommand/vpc.yaml --debug  . 

helm upgrade -i -n forge-system vpc --values values.yaml  --values environments/$environmentfleetcommand/vpc-site.yaml --debug .
```