# Local Kubernetes workflow

Nov 2022: Not currently used, prefer the docker-compose workflow.

# STILL A WIP!!!

Make sure you have followed all the steps [Local environment prep](../development.md#local-environment-prep) and are on the VPN.

```
cargo make kind
```

If you need to rerun that command you may need to delete the cluster first, command is further down.

Make sure you have the following installed prior to attempting to start Kind.
* golang (vpc)
* rust
* cargo make (cargo install cargo-make)
* docker

### Running binaries from your workstation in a kubernetes pod

To run forge binaries which are built on your local workstation, inside
a container we will use the `hostPath` resource.

In order for this to work -

1. copy `dev/kube/overlays/local/forge/override_api_image.json.example` to
`dev/kube/overlays/local/forge/override_api_image.json`
2. change the `value` field in `override_api_image.json` to a docker container
that matches your workstation operating system. (Ubuntu:focal is default)

Once that is set, `cd $REPO_ROOT`

```
cargo make kind
```

`forge-system` is the namespace where `forge-provisioner` and `forge-vpc` components
are running

If for some reason you need to delete the cluster and start over:
```
kind delete cluster --name forge-local
```
This will spin up a kind cluster, build and upload the carbide image, and apply
all the kubernetes primitives to expose carbide services.

When booting the test VM from your local workstation, use the new bridge that
Kind created for kubernetes.

To interact with carbide-api use the url `https://127.0.0.1:11079`

To view logs for a particular application, the most straightforward way is to
```
kubectl get pods -A
kubectl logs <podname> -f
```

You can also reference pods by labels (metadata -> labels) which are defined
in podspec or deploymentspec files.

```
kubectl logs -n default -l app=carbide-dhcp -f
```
