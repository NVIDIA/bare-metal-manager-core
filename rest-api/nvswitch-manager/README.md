# NV-Switch Manager

NV-Switch Manager is a gRPC service for managing NVIDIA DGX GB200 NVLink Switch Trays in datacenters. The service provides a control plane to register devices, manage credentials securely, query inventory, control power state, and orchestrate firmware upgrades for BMC, CPLD, BIOS, and NVOS components.

## At-a-Glance

1. gRPC API: internal/proto/v1
2. Orchestration: pkg/nvswitchmanager
3. Redfish access: pkg/redfish (thin wrapper around gofish)
4. Firmware management: pkg/firmwaremanager (worker pool, upgrade strategies, update tracking)
5. Registry: pkg/nvswitchregistry (Postgres or InMemory), pkg/db (Bun ORM + pgx)
6. Credentials: pkg/credentials (NICo Core, read-only; or InMemory, seeded locally)

## Architecture Overview
The service is layered with clear separation of responsibilities:

1. API (gRPC) — internal/service
    1. NVSwitchManagerServer implements RPCs for device registration, inventory queries, power control, and firmware management.
    2. Protobuf schema in internal/proto/v1 encapsulates the public service surface.
2. Orchestration — pkg/nvswitchmanager
    1. Central coordinator that wires the NV-Switch registry, credential manager, firmware manager, and Redfish/SSH client sessions per request.
    2. Stateless at the orchestration layer; state is delegated to backends.
3. Device Access — pkg/redfish, pkg/sshclient
    1. Encapsulates Redfish operations (query chassis/manager, power actions, firmware upload).
    2. SSH client for NVOS-level operations.
4. Firmware Management — pkg/firmwaremanager
    1. Background worker pool with configurable concurrency.
    2. Multiple update strategies (SSH, Redfish, Script).
    3. State machine: QUEUED → POWER_CYCLE → COPY → UPLOAD → INSTALL → VERIFY → COMPLETED/FAILED.
    4. Upgrade execution with PostgreSQL-backed update tracking.
5. NV-Switch Registry — pkg/nvswitchregistry
    1. Stores NV-Switch tray identity and routing attributes (MAC, IP, vendor, rack ID).
    2. Implementations: Postgres (prod), InMemory (dev/tests).
    3. Authoritative source of device inventory for the service.
6. Secrets: Credential Manager — pkg/credentials
    1. Retrieves per-device credentials keyed by BMC MAC address. Against NICo
       Core it is strictly read-only: Core owns switch credential storage and
       rotation, keeping them envelope-encrypted in Postgres, so NSM never
       writes them.
    2. Implementations: NICo Core over mTLS gRPC (prod), InMemory (dev/tests).
       The in-memory store has no Core to read from, so registration seeds it
       from the credentials on the request; those are ignored in Core mode.
    3. Explicitly separated from the device registry to isolate secret material.

This architecture emphasizes stateless orchestration at the service layer (driven by gRPC), separation of concerns for identity (device registry) and secrets (credential manager), firmware lifecycle management with background workers and upgrade strategies, and a clean boundary to device access through Redfish and SSH client wrappers. The design favors idempotency where possible, supports both in-memory and persistent backends, and treats firmware as a first-class workflow with update tracking and well-defined error semantics.

## gRPC API
Service definition: internal/proto/v1/nvswitch-manager.proto

## Local Development

This section provides a repeatable local development workflow using Docker Compose and helper scripts. It stands up Postgres, runs database migrations, starts the gRPC service, and verifies via grpcui. It is service-focused and assumes you are iterating on the NV-Switch Manager server.

### Prerequisites
1. Docker and Docker Compose
2. Go toolchain (1.26.4+)
3. grpcui (optional) to exercise the gRPC API
4. psql client (optional) for DB inspection

### 1. Start local infrastructure (Postgres)
```bash
docker compose up -d
```

### 2. Build the service binary

```bash
go build -o nvswitch-manager
```

### 3. Run DB migrations (create/drop tables)
```bash
# create initial tables
./nvswitch-manager migrate --host localhost --port 5432 --dbname nsmdatabase --user nsmuser --password nsmpassword

# roll back (drop tables)
./nvswitch-manager migrate --host localhost --port 5432 --dbname nsmdatabase --user nsmuser --password nsmpassword --rollback
```

### 4. Start the NV-Switch Manager gRPC service

For local work, run in-memory — no database, no NICo Core, no certificates:

```bash
./nvswitch-manager serve -d InMemory
```

Persistent mode uses Postgres for inventory and NICo Core for credentials.

> **Core version dependency.** Persistent mode calls two Core RPCs that are not
> in older releases: `GetSwitchBmcCredentials`, and `GetSwitchNvosCredentials`
> with the `bmc_mac_addr` selector. **Upgrade nico-api before nico-flow.**
> There is no fallback path — NSM keys credentials by BMC MAC and holds no
> Carbide `SwitchId` — so against an older Core every credential lookup fails
> with `Unimplemented` or `InvalidArgument`. NSM surfaces that error rather
> than proceeding with a stale credential.

Credential lookups dial Core over mTLS with the SPIFFE certificates in `CERTDIR`
(default `/var/run/secrets/spiffe.io`), and the Core address below is a
cluster-internal Service DNS name, so **these commands are meant to run in the
cluster**. To run them from a workstation you need the certificates on disk and
a reachable Core endpoint (e.g. `kubectl port-forward` plus a `localhost:` URL).

Supply the database credentials through the `DB_USER` / `DB_PASSWORD`
environment variables. Every flag below has an environment fallback, and
`--db_user` / `--db_password` equivalents are deliberately omitted from these
examples: arguments are visible in the process list and shell history.

```bash
# Prompt for the password rather than typing it as a command argument or an
# `export` that lands in shell history.
read -r  -p "DB user: "     DB_USER
read -rs -p "DB password: " DB_PASSWORD
printf '\n'
export DB_USER DB_PASSWORD

# minimal (reads DB_* and NICO_CORE_API_URL from the environment)
./nvswitch-manager serve -d Persistent

# explicit flags
./nvswitch-manager serve \
  --datastore Persistent \
  --port 50051 \
  --db_port 5432 \
  --db_host localhost \
  --db_name nsmdatabase \
  --core_api_url nico-api.nico-system.svc.cluster.local:1079

# short flags
./nvswitch-manager serve \
  -d Persistent \
  -p 50051 \
  -r 5432 \
  -o localhost \
  -n nsmdatabase \
  -a nico-api.nico-system.svc.cluster.local:1079
```

### 5. Exercise the API via grpcui
```bash
grpcui -plaintext localhost:50051
```
