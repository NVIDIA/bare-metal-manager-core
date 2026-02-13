# Site Setup Guide

This page outlines the software dependencies for a Kubernetes-based install of NVIDIA Bare Metal Manager (BMM). It includes the *validated baseline* of software dependencies,
as well as the *order of operations* for site bringup, including what you must configure if you already operate some of the common services yourself.

**Important Notes**

- All unknown values that you must supply contain explicit placeholders like `<REPLACE_ME>`.

- If you *already run* one of the core services (e.g. PostgreSQL, Vault,
  cert‑manager, Temporal), follow the **If you already have this service**
  checklist for that service.

- If you *don't already have a core service*, deploy the **Reference version** (images
  and versions below) and apply the configuration under **If you deploy the reference version**.

## Validated Baseline

This section lists all software dependencies, including the versions validated for this release of BMM.

### Kubernetes and Node Runtime

- **Control plane**: Kubernetes v1.30.4 (server)

- **Nodes**: kubelet v1.26.15, container runtime containerd 1.7.1

- **CNI**: Calico v3.28.1 (node & controllers)

- **OS**: Ubuntu 24.04.1 LTS

### Networking

- **Ingress**: Project Contour v1.25.2 (controller) + Envoy v1.26.4 (daemonset)

- **Load balancer**: MetalLB v0.14.5 (controller and speaker)

### Secret and Certificate Plumbing

- **External Secret Management System:** External Secrets Operator v0.8.6

- **Certificate Manager**: cert‑manager v1.11.1 (controller/webhook/CA‑injector)

  - Approver‑policy v0.6.3 (Pods present as cert-manager, cainjector, webhook, and policy controller.)

### State and Identity

- **PostgreSQL**: Zalando Postgres Operator v1.10.1 + Spilo‑15 image 3.0‑p1 (Postgres 15)

- **Vault**: Vault server v1.14.0, vault‑k8s injector v1.2.1

### Temporal and Search

- **Temporal server**: Temporal Server v1.22.6 (frontend/history/matching/worker)

  - Admin tools v1.22.4, UI v2.16.2

- **Temporal visibility**: Elasticsearch 7.17.3

### Monitoring and Telemetry (OPTIONAL)

These components are not required for BMM setup, but are recommended site metrics.

- **Monitoring System**:  Prometheus Operator v0.68.0; Prometheus v2.47.0; Alertmanager v0.26.0

- **Monitoring Platform**: Grafana v10.1.2; kube‑state‑metrics v2.10.0

- **Telemetry Processing**: OpenTelemetry Collector v0.102.1

- **Log aggregator**: Loki v2.8.4

- **Host Monitoring** Node exporter v1.6.1

### BMM Components

The following services are installed during the BMM installation process.

- **Carbide core (forge‑system)**: nvmetal-carbide:latest

- **cloud‑api**: registry.example.com/carbide/cloud-api:latest

- **cloud‑workflow**: registry.example.com/carbide/cloud-workflow:latest

- **cloud‑cert‑manager (credsmgr)**: registry.example.com/carbide/cloud-cert-manager:latest

- **elektra-site-agent**: registry.example.com/carbide/forge-elektra:latest

## Order of Operations

This section provides a high-level order of operations for installing components:

1. Cluster and networking ready

   - Kubernetes, containerd, and Calico (or conformant CNI)

   - Ingress controller (Contour/Envoy) + LoadBalancer (MetalLB or cloud LB)

   - DNS recursive resolvers and NTP available

2. Foundation services (in the following order)

   - **External Secrets Operator (ESO) - Optional**

   - **cert‑manager**: Issuers/ClusterIssuers in place

   - **PostgreSQL**: DB/role/extension prerequisites below

   - **Vault**: PKI engine, K8s auth, policies/paths

   - **Temporal**: server up; register namespaces

3.  Carbide core (forge‑system)

   - carbide-api and supporting services (DHCP/PXE/DNS/NTP as required)

4.  Carbide REST components

    - Deploy cloud‑api, cloud‑workflow (cloud‑worker & site‑worker), and cloud‑cert‑manager (credsmgr)

    - Seed DB and register Temporal namespaces (cloud, site, then site UUID)

    - Create OTP and bootstrap secrets for elektra‑site‑agent; roll restart it.

5.  Monitoring

    - Prometheus operator, Grafana, Loki, OTel, node exporter

## Installation Steps

This section provides additional details for each set of components that you need, including additional configuration steps if you already have some of the components.

### External Secrets Operator (ESO)

**Reference version**: `ghcr.io/external-secrets/external-secrets:v0.8.6`

You must provide the following:

- A SecretStore/ClusterSecretStore pointing at **Vault** and, if
  applicable, a Postgres secret namespace.

- ExternalSecret objects similar to these (namespaces vary by
  component):

  - `forge-roots-eso`: Target secret `forge-roots` with keys` site-root`,
    `forge-root`

  -  DB credentials ExternalSecrets per namespace (e.g `clouddb-db-eso : forge.forge-pg-cluster.credentials`)

-   Ensure an image pull secret (e.g. `imagepullsecret`) exists in the
    namespaces that pull from your registry.

### cert‑manager (TLS and Trust)

**Reference versions**:

-   **Controller/Webhook/CAInjector**: `v1.11.1`

-   **Approver‑policy**: `v0.6.3`

-   **ClusterIssuers** present: `self-issuer`, `site-issuer`, `vault-issuer`, `vault-forge-issuer`

**If you already have cert‑manager**:

- Ensure the version is greater than `v1.11.1`.

- Your `ClusterIssuer` objects must be able to issue the following:

    - Cluster internal certs (service DNS SANs)
    - Any externally‑facing FQDNs you choose

- Approver flows should allow your teams to create Certificate resources for the NVCarbide namespaces.

**If you deploy the reference version**:

-   Install cert‑manager `v1.11.1` and `approver‑policy v0.6.3`.

-   Create ClusterIssuers matching your PKI: `<ISSUER_NAME>`.

-   Typical **SANs** for NVFORGE services include the following:

    -   Internal service names (e.g. `carbide-api.<ns>.svc.cluster.local`, `carbide-api.forge`)

    -   Optional external FQDNs (your chosen domains)

### Vault (PKI and Secrets)

**Reference versions**:

-   **Vault server**: `v1.14.0` (HA Raft)

-   **Vault injector (vault‑k8s)**: `v1.2.1`

**If you already have Vault**:

-   Enable PKI engine(s) for the root/intermediate CA chain used by NVFORGE components (where
    your `forge-roots`/`site-root` are derived).

-   Enable K8s auth at path `auth/kubernetes` and create roles that
    map service accounts in the following namespaces: `forge-system`, `cert-manager`, `cloud-api`, `cloud-workflow`, `elektra-site-agent`

-   Ensure the following policies/paths (indicative):

    -   KV v2 for application material: `<VAULT_PATH_PREFIX>/kv/*`

    -   PKI for issuance: `<VAULT_PATH_PREFIX>/pki/*`

**If you deploy the reference version**:

-   Stand up Vault **1.14.0** with TLS (server cert for
    `vault.vault.svc`).

-   Configure the following environment variables:

    - `VAULT_ADDR` (cluster‑internal URL, e.g. `https://vault.vault.svc:8200` or `http://vault.vault.svc:8200` if testing)

    - KV mounts and PKI roles. Components expect the following environment variables:

      - `VAULT_PKI_MOUNT_LOCATION`
      - `VAULT_KV_MOUNT_LOCATION`
      - `VAULT_PKI_ROLE_NAME=forge-cluster`

-   Injector (optional) may be enabled for sidecar‑based secret injection.

```{note}
Vault is used by the following components:

-   **carbide‑api** consumes Vault for PKI and secrets (env VAULT\_\*).

-   **credsmgr** interacts with Vault for CA material exposed to the
    site bootstrap flow.
```

### PostgreSQL (DB)

**Reference versions**:

-   **Zalando Postgres Operator**: `v1.10.1`

-   **Spilo‑15 image**: `3.0‑p1` (Postgres `15`)

**If you already have Postgres**

-   Provide a database `<POSTGRES_DB>` and role `<POSTGRES_USER>` with
    password `<POSTGRES_PASSWORD>`.

-   Enable **TLS** (recommended) or allow secure network policy between
    DB and the NVCarbide namespaces.

-   Create extensions (the apps expect these):

    ```bash
    CREATE EXTENSION IF NOT EXISTS btree_gin;
    CREATE EXTENSION IF NOT EXISTS pg_trgm;
    ```

    This can be done with a call like the following:

    ```bash
    psql "postgres://<POSTGRES_USER>:<POSTGRES_PASSWORD>@<POSTGRES_HOST>:<POSTGRES_PORT>/<POSTGRES_DB>?sslmode=<POSTGRES_SSLMODE>" \
        -c 'CREATE EXTENSION IF NOT EXISTS btree_gin;' \
        -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'
    ```

-   Make the DSN available to workloads via ESO targets (per‑namespace
    credentials). These are some examples:

    -   `forge.forge-pg-cluster.credentials`
    -   `forge-system.carbide.forge-pg-cluster.credentials`
    -   `elektra-site-agent.elektra.forge-pg-cluster.credentials`

**If you deploy the reference version**:

-   Deploy the Zalando operator and a Spilo‑15 cluster sized for your
    SLOs.

-   Expose a ClusterIP service on `5432` and surface credentials
    through ExternalSecrets to each namespace that needs them.

### Temporal

**Reference versions**:

-   **Temporal server**: `v1.22.6` (frontend/history/matching/worker)

-   **UI**: `v2.16.2`

-   **Admin tools**: `v1.22.4`

-   **Frontend service endpoint (cluster‑internal)**: `temporal-frontend.temporal.svc:7233`

**Required namespaces**:

-   Base: `cloud`, `site`

-   Per‑site: The `<SITE_UUID>`

**If you already have Temporal**

-   Ensure the `frontend gRPC endpoint` is reachable from NVCarbide
    workloads and present the proper `mTLS`/CA if you require TLS.

-   Register namespaces:

    ```bash
    tctl --ns cloud namespace register
    tctl --ns site namespace register
    tctl --ns <SITE_UUID> namespace register (once you know the site UUID)
    ```

**If you deploy our reference**

-   Deploy Temporal as described above and expose port `:7233`.

-   Register the same namespaces as described above.
