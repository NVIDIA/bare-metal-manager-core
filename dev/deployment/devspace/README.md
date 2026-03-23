# Local Development with DevSpace

You can use [DevSpace](https://www.devspace.sh) to deploy ncx-infrastructure-core locally using mock hosts.

The process is broken into two steps:

1. Bootstrap Kubernetes prerequisites. (This only needs to be done once.)
2. Run `devspace deploy` to deploy code from this repo

The intent is that the app deploy path stays the same whether the prerequisites are:

- installed by the provided bootstrap script, or
- brought by the developer from elsewhere.

## Prerequisites Bootstrap

Run:

```bash
dev/deployment/devspace/bootstrap-prereqs.sh
```

By default this script assumes an empty cluster and will idempotently:

- install `cert-manager`
- create a local cert-manager issuer
- deploy a simple PostgreSQL instance
- deploy a simple Vault dev server
- configure Vault mounts and a local PKI role
- create the Secrets and ConfigMaps that the Helm chart expects
- write [`values.generated.yaml`](values.generated.yaml) for the app deploy step

It is safe to re-run. It uses `helm upgrade --install`, `kubectl apply`, and Vault checks before writing mounts/roles/secrets.

The bootstrap script is responsible for cluster-facing dependencies and generated wiring only. The repo deploy step does not install PostgreSQL, Vault, or cert-manager.

### Bring Your Own

You can skip the managed local services and still use the script to create only the chart wiring.

Examples:

```bash
LOCAL_DEV_INSTALL_POSTGRES=0 \
LOCAL_DEV_POSTGRES_HOST=my-postgres.postgres.svc.cluster.local \
LOCAL_DEV_POSTGRES_PORT=5432 \
LOCAL_DEV_POSTGRES_DB=carbide \
LOCAL_DEV_POSTGRES_USER=carbide \
LOCAL_DEV_POSTGRES_PASSWORD=secret \
dev/deployment/devspace/bootstrap-prereqs.sh
```

```bash
LOCAL_DEV_INSTALL_VAULT=0 \
LOCAL_DEV_VAULT_ADDR=https://vault.example.internal:8200 \
LOCAL_DEV_VAULT_TOKEN=... \
LOCAL_DEV_VAULT_KV_MOUNT=secrets \
LOCAL_DEV_VAULT_PKI_MOUNT=certs \
LOCAL_DEV_VAULT_AUTH_MODE=root-token \
dev/deployment/devspace/bootstrap-prereqs.sh
```

```bash
LOCAL_DEV_INSTALL_CERT_MANAGER=0 \
LOCAL_DEV_INSTALL_LOCAL_ISSUER=0 \
LOCAL_DEV_CERT_ISSUER_KIND=ClusterIssuer \
LOCAL_DEV_CERT_ISSUER_NAME=my-existing-issuer \
LOCAL_DEV_CERT_ISSUER_GROUP=cert-manager.io \
dev/deployment/devspace/bootstrap-prereqs.sh
```

Important:

- The script writes the generated Helm values file from these settings.
- For local Vault, the app uses root-token auth by setting `automountServiceAccountToken: false`.
- For external Vault, either keep `VAULT_AUTH_MODE=root-token` or supply your own compatible auth setup.

## Build And Deploy

Once the prerequisites are ready, run:

```bash
devspace deploy
```

DevSpace will:

- build the local runtime images from [`Dockerfile.api`](Dockerfile.api) and [`Dockerfile.machine-a-tron`](Dockerfile.machine-a-tron)
- deploy the Helm chart in [`helm/`](../../../helm)
- apply the local-only `machine-a-tron` Kubernetes objects from [`machine-a-tron.yaml`](machine-a-tron.yaml) with `kubectl`
- inject the built image names and DevSpace-generated tags into both deployments at runtime

The image builds are configured in [`devspace.yaml`](../../../devspace.yaml). Both Dockerfiles are multi-stage builds: the builder stage compiles the Rust binary inside Docker from the local `build-container-localdev` image, and the runtime stage copies only the finished binary and required runtime assets. DevSpace first checks whether `build-container-localdev` already exists locally and reuses it if present; otherwise it builds it from [`dev/docker/Dockerfile.build-container-x86_64`](../../../dev/docker/Dockerfile.build-container-x86_64). BuildKit cache mounts are used for Cargo registry, Cargo git checkouts, and Cargo target output so rebuilds stay fast without copying host build artifacts into the image.

The DevSpace images also use Dockerfile-specific ignore files: [`Dockerfile.api.dockerignore`](Dockerfile.api.dockerignore) and [`Dockerfile.machine-a-tron.dockerignore`](Dockerfile.machine-a-tron.dockerignore). This keeps the top-level [`.dockerignore`](../../../.dockerignore) aligned with the main branch for CI and release builds, while still giving the local DevSpace builds a small Docker context.

DevSpace watches the Rust workspace, toolchain metadata, and the runtime Dockerfile to decide when the image needs rebuilding.

The production Helm chart is still only responsible for the product services. `machine-a-tron` is deployed separately as plain local-only Kubernetes objects in [`machine-a-tron.yaml`](machine-a-tron.yaml), with DevSpace wiring in the local image tag and certificate issuer from [`devspace.yaml`](../../../devspace.yaml). The local API site config in [`values.base.yaml`](values.base.yaml) points BMC traffic at `machine-a-tron-bmc-mock.forge-system.svc.cluster.local:1266`.

Common usage:

```bash
devspace deploy
devspace deploy -n forge-system
devspace deploy --force-build
```

## Manual Equivalent

If you want to understand what DevSpace is doing for the app image, the configured build is effectively:

```bash
docker image inspect build-container-localdev >/dev/null 2>&1 || docker build --pull=false -t build-container-localdev -f dev/docker/Dockerfile.build-container-x86_64 .
docker build -t "carbide-api:<devspace-generated-tag>" -f dev/deployment/devspace/Dockerfile.api .
docker build -t "machine-a-tron:<devspace-generated-tag>" -f dev/deployment/devspace/Dockerfile.machine-a-tron .
```

DevSpace then deploys the Helm chart with the built `carbide-api` image wired into `global.image.repository` and `global.image.tag`, and applies the local-only `machine-a-tron` manifest with its image wired into the `Deployment` spec.

## Re-initializing  ncx-infra-controller-core to a clean slate

Once deployed, the `carbide-api` container will run and initialize its database, and the `machine-a-tron` container will run a set of mock machines, which will be discovered and ingested into the database, and run through the state machine until they reach a Ready state.

You can start over again (purging the resources from k8s) by running:

```bash
devspace purge -n forge-system
```

and it will delete the carbide-api and machine-a-tron deployments.

To clear out the carbide database to start from scratch again, run the nuke-postgres.sh helper script:

```bash
dev/deployment/devspace/nuke-postgres.sh
```

and the postgres database will be reset to an empty state, allowing you to deploy again:

```bash
devspace deploy -n forge-system
```

## Files

- [`bootstrap-prereqs.sh`](bootstrap-prereqs.sh)
- [`devspace.yaml`](../../../devspace.yaml)
- [`values.base.yaml`](values.base.yaml)
- [`values.generated.yaml`](values.generated.yaml)
- [`nuke-postgres.sh`](nuke-postgres.sh)
