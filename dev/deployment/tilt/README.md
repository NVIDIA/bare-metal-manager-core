# Local development with Tilt

Tilt runs the complete local NICo development stack from the repository's Helm
charts and Kubernetes sources. DevSpace remains available as a separate
workflow.

> [!WARNING]
> This workflow is intended only for local development and is
> provided as-is. Use it at your own risk.

## Requirements

- Docker
- Tilt
- Helm 3 or Helm 4, plus Python 3 for Tilt's `helm_resource` extension
- `kubectl` connected to a kind cluster

The Tiltfile refuses to load unless the active Kubernetes context starts with
`kind-`. This is stricter than Tilt's built-in local-cluster safety check and
prevents this development stack from targeting another cluster type.

## Start

From the repository root, run:

```bash
tilt up -f dev/deployment/tilt/Tiltfile
```

The default stack includes:

- cert-manager
- the CloudNativePG operator and one PostgreSQL cluster
- Vault in local development mode
- NICo API, BMC proxy, and machine-a-tron
- Temporal and its local namespaces
- Keycloak and the `nico-dev` realm
- NICo REST API, database migrations, certificate manager, site manager,
  workflow workers, and site agent
- NICo MCP
- automatic local site registration

Tilt forwards these endpoints:

| Service | URL |
| --- | --- |
| NICo Web UI | `https://localhost:1079/admin/` |
| Machine-A-Tron UI | `https://localhost:1266/` |
| REST API | `http://localhost:18388` |
| Keycloak | `http://localhost:18082` |
| MCP | `http://localhost:18080/mcp` |
| Temporal UI | `http://localhost:18233` |

All Tilt settings are in [`values.yaml`](values.yaml). NICo Core values are at
the document root, while the `tilt` section contains the prerequisite and REST
settings.

## Image builds

Core uses the existing Dockerfiles under
[`dev/deployment/devspace/`](../devspace). REST and MCP use the existing
Dockerfiles under [`rest-api/docker/local/`](../../../rest-api/docker/local).
The Tilt setup does not add or modify a Dockerfile.

Each deployable image has its own Tilt resource and rebuild control. Images build
once during startup, then wait for their resource's update button before
rebuilding. REST build contexts are restricted to the source directories copied
by that image's Dockerfile. Docker and Cargo or Go build caches are reused across
rebuilds.

## Optional profiles

The `tilt.profiles` switches in [`values.yaml`](values.yaml) control REST, MCP,
and DSX Exchange. REST brings Temporal and Keycloak, MCP automatically brings
REST, and DSX Exchange brings NATS. The committed defaults enable REST and MCP
and disable DSX Exchange.

Changes to `values.yaml` reload the running Tilt session. For temporary
overrides, use `tilt args`. Start only Core with:

```bash
tilt args -- --rest=false --mcp=false
```

Run REST without MCP with:

```bash
tilt args -- --rest=true --mcp=false
```

Add DSX Exchange with:

```bash
tilt args -- --dsx-exchange=true
```

Return to the values-file defaults with:

```bash
tilt args --clear
```

## Existing local clusters

An earlier draft of this Tilt setup deployed Core as one Helm release named
`nico`. Remove that release once before starting the component-based setup:

```bash
helm uninstall nico -n nico-system
```

Tilt and DevSpace deploy the same application object names and should not manage
the same cluster simultaneously. Before switching an existing DevSpace kind
cluster to Tilt, run:

```bash
LOCAL_DEV_INSTALL_REST_PREREQS=0 devspace purge -n nico-system
```

To switch back to DevSpace, remove the Tilt stack and use the existing DevSpace
bootstrap and deploy commands:

```bash
tilt down -f dev/deployment/tilt/Tiltfile
dev/deployment/devspace/bootstrap-prereqs.sh
devspace deploy -n nico-system
```

## Stop and remove

Stopping `tilt up` leaves the stack running. Remove Tilt-managed resources with:

```bash
tilt down -f dev/deployment/tilt/Tiltfile
```
