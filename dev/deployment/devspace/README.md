# Local Development with DevSpace

You can use [DevSpace](https://www.devspace.sh) to deploy the complete local infra-controller stack. The deployment connects the REST services to the real Core gRPC API, while `machine-a-tron` supplies the mock hosts.

The process is broken into two steps:

1. Bootstrap Kubernetes prerequisites. (This only needs to be done once per cluster.)
2. Run `devspace deploy` to deploy code from this repo

The intent is that the app deploy path stays the same whether the prerequisites are:

- installed by the provided bootstrap script, or
- brought by the developer from elsewhere.

## Prerequisites Bootstrap

The bootstrap script operates on the current Kubernetes context and does not require a particular Kubernetes distribution. The provided full-stack deploy path uses kind-specific hooks to load locally built images into contexts named `kind-<cluster>`.

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
- create a separate REST database in the local PostgreSQL instance
- deploy Temporal and create its `cloud` and `site` namespaces
- deploy the local Keycloak realm
- share the Core CA with REST so the site agent can use mTLS with Core
- create the Secrets and ConfigMaps that the Helm chart expects
- write [`values.generated.yaml`](values.generated.yaml) for the app deploy step

It is safe to re-run. It uses `helm upgrade --install`, `kubectl apply`, and Vault checks before writing mounts/roles/secrets.

The bootstrap script is responsible for cluster-facing dependencies and generated wiring only. The repo deploy step does not install PostgreSQL, Vault, cert-manager, Temporal, or Keycloak.

### Bring Your Own

You can skip the managed local services and still use the script to create only the chart wiring.

Examples:

```bash
LOCAL_DEV_INSTALL_POSTGRES=0 \
LOCAL_DEV_INSTALL_REST_PREREQS=0 \
LOCAL_DEV_POSTGRES_HOST=my-postgres.postgres.svc.cluster.local \
LOCAL_DEV_POSTGRES_PORT=5432 \
LOCAL_DEV_POSTGRES_DB=nico \
LOCAL_DEV_POSTGRES_USER=nico \
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
LOCAL_DEV_INSTALL_REST_PREREQS=0 \
LOCAL_DEV_CERT_ISSUER_KIND=ClusterIssuer \
LOCAL_DEV_CERT_ISSUER_NAME=my-existing-issuer \
LOCAL_DEV_CERT_ISSUER_GROUP=cert-manager.io \
dev/deployment/devspace/bootstrap-prereqs.sh
```

Important:

- The script writes the generated Helm values file from these settings.
- For local Vault, the app uses root-token auth by setting `automountServiceAccountToken: false`.
- For external Vault, either keep `VAULT_AUTH_MODE=root-token` or supply your own compatible auth setup.
- `LOCAL_DEV_INSTALL_TEMPORAL=0` and `LOCAL_DEV_INSTALL_KEYCLOAK=0` skip those managed services.
- `LOCAL_DEV_INSTALL_REST_PREREQS=0` preserves the Core-only bootstrap behavior.
- A full-stack deployment expects PostgreSQL at `postgres.postgres.svc.cluster.local` and requires the `nico_rest`, `keycloak`, `temporal`, and `temporal_visibility` databases and roles when the local PostgreSQL installation is skipped. A nondefault PostgreSQL host is supported only by the Core-only path.
- The Core and REST services share one PostgreSQL server but use separate `nico` and `nico_rest` databases because both schemas contain tables such as `machines` and `instances`.

## Build And Deploy

Once the prerequisites are ready, run:

```bash
devspace deploy
```

DevSpace will:

- build the local runtime images from [`Dockerfile.api`](Dockerfile.api), [`Dockerfile.bmc-proxy`](Dockerfile.bmc-proxy), and [`Dockerfile.machine-a-tron`](Dockerfile.machine-a-tron)
- build the REST API, workflow, site-manager, site-agent, database migration, certificate-manager, and MCP images from [`rest-api/docker/local`](../../../rest-api/docker/local)
- deploy the Helm chart in [`helm/`](../../../helm)
- deploy the REST umbrella, site-agent, and MCP charts in [`helm/rest`](../../../helm/rest)
- apply the local-only `machine-a-tron` Kubernetes objects from [`machine-a-tron.yaml`](machine-a-tron.yaml) with `kubectl`
- inject the built image names and DevSpace-generated tags into both deployments at runtime
- register a local REST site, configure its Temporal namespace, and confirm that the site agent establishes a Core gRPC connection

The image builds are configured in [`devspace.yaml`](../../../devspace.yaml). The Dockerfiles are multi-stage builds: the builder stage compiles the Rust binary inside Docker from the local `build-container-localdev` image, and the runtime stage copies only the finished binary and required runtime assets. DevSpace first checks whether `build-container-localdev` already exists locally and reuses it if present; otherwise it builds it from [`dev/docker/Dockerfile.build-container-x86_64`](../../../dev/docker/Dockerfile.build-container-x86_64). BuildKit cache mounts are used for Cargo registry, Cargo git checkouts, and Cargo target output so rebuilds stay fast without copying host build artifacts into the image.

The DevSpace images also use Dockerfile-specific ignore files: [`Dockerfile.api.dockerignore`](Dockerfile.api.dockerignore), [`Dockerfile.bmc-proxy.dockerignore`](Dockerfile.bmc-proxy.dockerignore), and [`Dockerfile.machine-a-tron.dockerignore`](Dockerfile.machine-a-tron.dockerignore). This keeps the top-level [`.dockerignore`](../../../.dockerignore) aligned with the main branch for CI and release builds, while still giving the local DevSpace builds a small Docker context.

DevSpace watches the Rust workspace, toolchain metadata, and the runtime Dockerfiles to decide when images need rebuilding.

The REST images use the existing local Dockerfiles and one shared per-run tag because the REST Helm charts intentionally consume a common repository and tag. On kind clusters, the pre-deploy hooks load all Core and REST images into the cluster selected by the current kube context.

The production Helm chart is still only responsible for the product services. `machine-a-tron` is deployed separately as plain local-only Kubernetes objects in [`machine-a-tron.yaml`](machine-a-tron.yaml), with DevSpace wiring in the local image tag and certificate issuer from [`devspace.yaml`](../../../devspace.yaml). The local API and BMC proxy configs in [`values.base.yaml`](values.base.yaml) point BMC traffic at `machine-a-tron-bmc-mock.nico-system.svc.cluster.local:1266`.

Common usage:

```bash
devspace deploy
devspace deploy -n nico-system
devspace deploy --skip-build -n nico-system
devspace deploy --force-build
```

The post-deploy setup uses temporary port-forwards to register the site and verifies that machines from Core are visible through the REST API. To keep the REST API and Keycloak available on localhost after `devspace deploy` exits, run these in separate terminals:

```bash
kubectl -n nico-rest port-forward service/nico-rest-api 18388:8388
kubectl -n nico-rest port-forward service/keycloak 18082:8082
```

Then acquire a local token and list the machines discovered through `machine-a-tron`:

```bash
TOKEN=$(curl -fsS -X POST http://localhost:18082/realms/nico-dev/protocol/openid-connect/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=nico-api' \
  -d 'client_secret=nico-local-secret' \
  -d 'grant_type=password' \
  -d 'username=admin@example.com' \
  -d 'password=adminpassword' | jq -r .access_token)
curl -fsS http://localhost:18388/v2/org/test-org/nico/machine \
  -H "Authorization: Bearer ${TOKEN}" | jq
```

To run the original Core-only deployment, skip the REST prerequisites during bootstrap and use the `core-only` profile:

```bash
LOCAL_DEV_INSTALL_REST_PREREQS=0 dev/deployment/devspace/bootstrap-prereqs.sh
devspace deploy --profile core-only
```

## Manual Equivalent

If you want to understand what DevSpace is doing for the runtime images, the configured build is effectively:

```bash
docker image inspect build-container-localdev >/dev/null 2>&1 || docker build --pull=false -t build-container-localdev -f dev/docker/Dockerfile.build-container-x86_64 .
docker build -t "nico-api:<devspace-generated-tag>" -f dev/deployment/devspace/Dockerfile.api .
docker build -t "nico-bmc-proxy:<devspace-generated-tag>" -f dev/deployment/devspace/Dockerfile.bmc-proxy .
docker build -t "machine-a-tron:<devspace-generated-tag>" -f dev/deployment/devspace/Dockerfile.machine-a-tron .
```

DevSpace then deploys the Helm chart with the built `nico-api` image wired into `global.image.repository` and `global.image.tag`, the built `nico-bmc-proxy` image wired into the `nico-bmc-proxy` chart values, and applies the local-only `machine-a-tron` manifest with its image wired into the `Deployment` spec. The REST images are built from the existing `rest-api/docker/local` Dockerfiles and are passed to the three existing REST Helm charts with the same generated tag.

## Resetting the local environment

Once deployed, the `nico-api` container will run and initialize its database, and the `machine-a-tron` container will run a set of mock machines, which will be discovered and ingested into the database, and run through the state machine until they reach a Ready state.

Reset the complete local environment by running:

```bash
devspace purge -n nico-system
```

When the current context is `kind-<cluster>`, the purge pipeline deletes and recreates that kind cluster with the same node image, then bootstraps clean prerequisites. This removes all Kubernetes state, including the Core and REST databases, Temporal namespaces and history, Vault data, Keycloak data, certificates, site registration, Helm releases, CRDs, and persistent volumes.

On any other Kubernetes context, the pipeline delegates to DevSpace's default purge behavior. It removes the deployments managed by this project without replacing the cluster or reinstalling separately managed prerequisites.

The host Docker images, BuildKit cache, and `.devspace` image metadata are outside the kind node and remain available. Redeploy the last built images without rebuilding them:

```bash
devspace deploy --skip-build -n nico-system
```

The pre-deploy hooks load the cached Core and REST images from the host Docker store into the new kind node. Omit `--skip-build` when the source or image definitions have changed since the last build.

To clear only the Core `nico` database, run the nuke-postgres.sh helper script:

```bash
dev/deployment/devspace/nuke-postgres.sh
```

This helper does not reset the REST, Keycloak, or Temporal databases, the REST site registration, or Temporal namespaces. After resetting Core state, deploy again with:

```bash
devspace deploy -n nico-system
```

## Files

- [`bootstrap-prereqs.sh`](bootstrap-prereqs.sh)
- [`reset-kind-cluster.sh`](reset-kind-cluster.sh)
- [`setup-rest-integration.sh`](setup-rest-integration.sh)
- [`devspace.yaml`](../../../devspace.yaml)
- [`values.base.yaml`](values.base.yaml)
- [`values.generated.yaml`](values.generated.yaml)
- [`nuke-postgres.sh`](nuke-postgres.sh)
