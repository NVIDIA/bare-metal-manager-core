# Forge Site Bootstrap / Forge Install

There are two distinct workflows to bootstrap a new site and install
Forge.

If the site is a Fleet Command site, then follow the directions [for
installing under Fleet Command](#fleet-command-environment)

If the site is not a Fleet Command site, then follow the directions [for installing using Helm](#helm)

# Fleet Command environment

For Fleet Command base Forge installs, look at [SRE Workflow doc for
Forge](https://docs.google.com/document/d/1tuETD9chsOO03nYaQSYPNPLfYuA7_cl15uAxhAJ0a5g/edit#heading=h.ajik68ox788i)


# HELM
Before proceeding, make sure you have completed the instructions for [Setting up Helm](../kubernetes/helm.md)

Next, clone the [forge-deployment git repo](https://gitlab-master.nvidia.com/nvmetal/forge-deployment)

**NOTE**
>If the environment _requires_ changes, edit the YAML file corresponding
>to the component that needs configuration changes. e.g., `environment/$environment/<file>.yaml`. 

## Example configuration update
In the `dev1` environment, there is one Kubernetes host. Our default
configuration assumes three hosts for Vault. The installation will hang and
eventually time out without changing the Vault configuration.
 
Edit `environment/$environment/fleetcommand/vault.yaml` overriding the
vault-specific configuration. Changing the layout to a single
host allows the installation to succeed and Vault to start

```yaml
vault:
  server:
    ha:
      enabled: true
      replicas: 1
      raft:
        enabled: true
        setNodeId: true
        config: |
          ui = false
          listener "tcp" {
            address = "[::]:8200"
            cluster_address = "[::]:8201"
            tls_cert_file = "/vault/userconfig/forgeca-vault/tls.crt"
            tls_key_file = "/vault/userconfig/forgeca-vault/tls.key"
            tls_client_ca_file = "/vault/userconfig/forgeca-vault/ca.crt"
          }

            storage "raft" {
              path = "/vault/data"
              retry_join {
                leader_tls_servername = "vault-0.vault-internal"
                leader_api_addr = "https://vault-0.vault-internal:8200"
                leader_ca_cert_file = "/vault/userconfig/vault-raft-tls/ca.crt"
                leader_client_cert_file = "/vault/userconfig/vault-raft-tls/tls.crt"
                leader_client_key_file = "/vault/userconfig/vault-raft-tls/tls.key"
              }

              autopilot {
                cleanup_dead_servers = "true"
                last_contact_threshold = "200ms"
                last_contact_failure_threshold = "10m"
                max_trailing_logs = 250000
                min_quorum = 1
                server_stabilization_time = "10s"
              }

            }

            service_registration "kubernetes" {}

```

## Kubed
---
Install appscode/kubed for synchronizing `imagepullsecret` to current/future namespaces

For `kubelet` to pull containers from container registries `nvcr.io` and
`stg.nvcr.io`, `imagepullsecret` must first exist in the `default` namespace.
`appscode/kubed` handles synchronizing the Kubernetes `secret` from the
default namespace to new/existing namespaces.

TODO: appscode/kubed mirror locally

```sh
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

## cert-manager
---
Forge has a dependency on `Vault`, `cert-manager`, and `cert-manager-csi-driver-spiffe`.

Carbide pods will fail to start without these components installed and configured correctly.

```sh
helm upgrade -i -n cert-manager cert-manager --values environments/$environment/fleetcommand/cert-manager.yaml --create-namespace --atomic --debug .
```

Once the install completes, you need manually approve two `CertificateRequests`:

```sh
kubectl cert-manager approve -n vault $(kubectl get cr -n vault -ojsonpath='{.items[0].metadata.name}')

kubectl cert-manager approve -n vault $(kubectl get cr -n vault -ojsonpath='{.items[1].metadata.name}')
```

## local-path-provisioner
---
**NOTE**
> This is sometimes already installed.  You can confirm an install by
> running `kubectl get pods -n local-path-storage` if you see pods
> running you can safely skip this step

```sh
helm upgrade -i -n local-path-storage local-path-provisioner --create-namespace --values environments/$environment/fleetcommand/local-path.yaml --atomic --debug .
```

## Vault
---

```sh
helm upgrade -i -n vault vault --values environments/$environment/fleetcommand/vault.yaml --debug --atomic .
```

## Postgres-Operator
---

```sh
helm upgrade -i -n postgres postgres-operator --values environments/$environment/fleetcommand/postgres-operator.yaml --create-namespace --debug .
```

## ForgeDB
---

This `chart` creates the forge database, sets up the user/pass, and the Kubernetes `service` that carbide components will use.

```sh
helm upgrade -i -n postgres forgedb --values environments/$environment/fleetcommand/forgedb.yaml --debug --atomic .
```

## carbide
---
This `chart` handles the installation of all Carbide related components.

```sh
helm upgrade -i -n forge-system carbide --values environments/$environment/fleetcommand/forge.yaml --debug  .
```
 
## vpc
---

VPC has three `charts` that are installed and upgraded separately.

1. `vpc-crds` - CRD definitions for VPC.  These are maintained in a separate `chart `  to allow upgrades without impacting VPC itself
2. `vpc` - The actual software VPC. 
3. `vpc-site` - Site-specific VPC resources such as `administration-resource-group` and  `configurationResourcePool`

```sh
helm upgrade -i -n forge-system vpc --values environments/$environment/fleetcommand/vpc-crds.yaml --debug .

helm upgrade -i -n forge-system vpc --values environments/$environment/fleetcommand/vpc.yaml --debug  . 

helm upgrade -i -n forge-system vpc --values environments/$environment/fleetcommand/vpc-site.yaml --debug .
```