# Tenant Management

Operator guide for tenant creation, resource allocation, and instance provisioning on NICo, using nicocli (REST API CLI) as the primary tool.

This is a Day 1 (Configuration) activity in NICo's lifecycle model -- the phase after hardware has been discovered, validated, and ingested (Day 0). Day 1 is when operators configure tenant boundaries, define resource allocations, and provision instances so tenants can consume bare-metal infrastructure.

The primary tool throughout this guide is `nicocli`, the CLI client that wraps the NICo REST API. Every REST endpoint is available as a CLI command, and nicocli handles authentication, token refresh, and multi-environment configuration automatically. The carbide-admin-cli (which talks to the Core gRPC API) is referenced only where an operation has no REST API equivalent.

## Before You Start

This guide assumes you have completed the [Quick Start Guide](../getting-started/quick-start.md), which covers NICo deployment, site creation, and host discovery (Day Zero). You should already have:

- A running NICo deployment with healthy REST API, database, Temporal workflow engine, and at least one site controller.
- At least one site registered and in `Registered` status, with machines discovered and available for allocation.
- `nicocli` installed (`make nico-cli` from the infra-controller-rest repo) and reachable on `$PATH`.

> **Note on CLI naming**: Older docs reference `carbidecli` (built via `make carbide-cli`). It's the same source under a previous name. This guide uses `nicocli` (built via `make nico-cli`) consistently.

For nicocli mechanics and conventions (flag ordering, `api.name` selection, `--data` vs flag forms, output formats, pagination, `--debug`), see the nicocli reference guide. The examples in this guide assume you've read it.

### Roles Required

NICo's authorization model has three roles, all managed in the upstream identity provider (any OIDC-compatible IdP, e.g. Keycloak):

| Role | Scope | Required For |
|------|-------|-------------|
| Provider Admin (`PROVIDER_ADMIN`) | Infrastructure provider org | Creating allocations, managing tenant accounts, managing sites and instance types |
| Provider Viewer (`PROVIDER_VIEWER`) | Infrastructure provider org | Read-only access to provider-scoped resources |
| Tenant Admin (`TENANT_ADMIN`) | Tenant org | Managing the tenant's instances, VPCs, subnets, SSH keys |

A single user can hold roles in multiple orgs simultaneously. On dev/service-account orgs, one user typically holds both Provider Admin and Tenant Admin in the same org.

### Authentication

The Quick Start covers `nicocli login` end-to-end for Keycloak-backed deployments (the default for `setup.sh` installs). For other identity providers and for the static-token / token-command flows useful in automation, see the nicocli reference guide.

### Verifying Connectivity

Confirm that nicocli can reach the API and your credentials are valid:

```
nicocli site list
nicocli user get
```

`nicocli user get` returns your identity as NICo sees it.

## Creating a Tenant

### How Tenant Creation Works

NICo uses a lazy creation model for tenants. There is no explicit "create tenant" API call. Instead, a tenant record is automatically created the first time a Tenant Admin retrieves the current tenant for their organization:

```
nicocli tenant get-current-tenant
```

If no tenant exists for the configured org, NICo creates one and returns it. If a tenant already exists, the same command returns the existing record. The operation is idempotent.

Each tenant maps one-to-one to an organization in the configured identity provider. The tenant's identity (org name, display name) is derived from the IdP's org metadata -- there are no separate fields to supply.

In TUI mode:

```
nicocli tui
> tenant current
```

### Required Conditions

- The authenticated user must be a member of the organization specified in the nicocli config (`api.org`).
- The user must hold the Tenant Admin role within that org.

If either condition is not met, the API returns HTTP 403. NICo trusts whatever the IdP says in the token's claims, so getting these conditions met is an IdP administration task -- it is not done through nicocli or the NICo API. The [Quick Start Guide](../getting-started/quick-start.md) walks through the bundled Keycloak reference implementation (a dev Keycloak deployed by `setup.sh` with a pre-loaded realm), which is the simplest path for first-time setup. For production, point NICo at any OIDC-compatible IdP (Keycloak, Okta, Auth0, your existing enterprise IdP) by configuring the `issuers` block in `carbide-rest-api`'s config -- see [`getting-started/installation-options/reference-install.md`](../getting-started/installation-options/reference-install.md) for the deployment-side wiring.

### Worked Example

```
$ nicocli tenant get-current-tenant
{
  "capabilities": {
    "targetedInstanceCreation": true
  },
  "created": "2026-04-23T01:11:07.452525Z",
  "id": "<tenant-uuid>",
  "org": "acme-corp",
  "orgDisplayName": "Acme Corporation",
  "updated": "2026-04-28T18:20:10.438572Z"
}
```

| Field | Description |
|-------|-------------|
| `id` | UUID identifier for the tenant, used in all subsequent API calls |
| `org` | Organization name (matches your config `api.org`) |
| `orgDisplayName` | Human-readable name pulled from the IdP's org metadata |
| `capabilities.targetedInstanceCreation` | Whether this tenant can specify a particular machine ID when creating instances. Set during initial tenant creation: lazy-create via `tenant get-current-tenant` typically leaves it `false`; the service-account bootstrap path (`service-account get`) sets it `true` for self-tenants. |

### Verifying the Tenant

Check tenant health with the stats endpoint:

```
nicocli tenant get-current-tenant-stats
```

Example response for a tenant in active use:

```json
{
  "instance": {"error": 0, "pending": 0, "ready": 6, "registering": 0, "terminating": 0, "total": 6, "updating": 0},
  "subnet": {"deleting": 0, "error": 0, "pending": 0, "provisioning": 0, "ready": 0, "total": 0},
  "tenantAccount": {"error": 0, "invited": 0, "pending": 0, "ready": 1, "total": 1},
  "vpc": {"deleting": 0, "error": 0, "pending": 0, "provisioning": 0, "ready": 2, "total": 2}
}
```

A freshly created tenant shows all zeroes. In TUI mode: `tenant stats`. Status keys in the response are alphabetical, not lifecycle order.

### What Happens Behind the Scenes

When `GET /v2/org/{org}/nico/tenant/current` is called and no tenant exists, the API:

1. Validates org membership and the Tenant Admin role.
2. Creates a tenant record in the database with name, org, and display name pulled from the IdP claims in the token.
3. Links any pre-existing tenant account invitations referencing this org.
4. Returns the new tenant as JSON with HTTP 200.

Subsequent calls return the existing tenant. If the org's display name has changed in the IdP, NICo silently updates it on the next call.

## Establishing a Tenant Account

A tenant alone cannot consume infrastructure -- it needs a tenant account that links it to an infrastructure provider. This is a provider-side operation requiring the Provider Admin role.

### Creating the Link

```
nicocli tui
> tenant-account create
```

The TUI prompts for the infrastructure provider ID and the tenant org name. Non-interactive (using individual flags):

```
nicocli tenant-account create --infrastructure-provider-id <provider-uuid> --tenant-org acme-corp
```

The tenant account starts in `Invited` status. Listing tenant accounts requires a filter flag -- the bare `nicocli tenant-account list` returns HTTP 400:

```
nicocli tenant-account list --tenant-id <tenant-uuid>
nicocli tenant-account list --infrastructure-provider-id <provider-uuid>
```

Example tenant account detail (Ready, with active allocations):

```json
{
  "accountNumber": "<auto-generated>",
  "allocationCount": 4,
  "id": "<account-uuid>",
  "infrastructureProviderId": "<provider-uuid>",
  "infrastructureProviderOrg": "acme-infra",
  "status": "Ready",
  "subscriptionId": null,
  "subscriptionTier": null,
  "tenantContact": null,
  "tenantId": "<tenant-uuid>",
  "tenantOrg": "acme-corp"
}
```

`accountNumber` is auto-generated. `allocationCount` is a live count of allocations under this account. `tenantContact` records the user who accepted the invitation (null until accepted, or null when the same org is both provider and tenant).

### Accepting the Invitation (Tenant Side)

The tenant admin must accept the invitation to transition the account to `Ready`. The non-interactive form sends an empty PATCH body -- note the flag-first ordering:

```
nicocli tenant-account update --data '{}' <account-id>
```

TUI:

```
nicocli tui
> tenant-account update
```

Only accounts in `Invited` status can be accepted. Attempting to update a `Ready` account returns the verified error:

```
$ nicocli tenant-account update --data '{}' <account-id>
Error: API error 400: Tenant Account status is not Invited
```

## Instance Types

Instance types define hardware classes -- they map a named category (like "GB200-NVL72" or "DGX-H100") to a set of physical machines with specific GPU, CPU, and network configurations. Before a tenant can create compute allocations, the instance types must exist and machines must be associated with them.

### How Instance Types Map to Hardware

Each instance type record includes:

- A name identifying the hardware class (e.g., `GB200-NVL72`)
- GPU count and type metadata
- Machine associations linking specific physical machines to the type

The site administrator defines instance types during Day Zero. NICo validates that machines associated with an instance type have compatible hardware before accepting the association.

### Viewing Instance Types

```
nicocli instance-type list --output table
```

The TUI provides richer detail:

```
nicocli tui
> instance-type list
> instance-type get
```

The detail view for an instance type includes an `allocationStats` section showing how many machines are assigned, allocated, and available (`maxAllocatable`). This tells you the upper bound for a new allocation's constraint value.

### Creating Instance Types (Provider Admin, gRPC Only)

Instance type creation is a gRPC operation via carbide-admin-cli:

```
carbide-admin-cli -c <core-api-url> instance-type create --name "GB200-NVL72" --gpu-count 72
carbide-admin-cli -c <core-api-url> instance-type associate --instance-type-id <id> --machine-id <machine-id>
```

See the Quick Start Guide, Step 7 for carbide-admin-cli access patterns. The REST API exposes instance type CRUD endpoints, but machine association management is currently gRPC-only.

## Assigning Resources with Allocations

An allocation grants a tenant access to infrastructure at a specific site. Without at least one allocation, a tenant cannot create instances, VPCs, or subnets. Allocations are provider-side operations requiring the Provider Admin role.

### Allocation Model

Each allocation ties together an infrastructure provider, a tenant, and a site, with exactly one allocation constraint that specifies:

| Resource Type | What It Controls | Constraint Value Meaning |
|--------------|-----------------|------------------------|
| `InstanceType` | Compute (bare-metal machines) | Number of machines of that instance type the tenant may use |
| `IPBlock` | Network (IP address space) | IPv4 prefix length of the sub-block carved from the parent IP block |

The only constraint type currently supported is `Reserved`, which guarantees the specified capacity. The API validator also accepts `OnDemand` and `Preemptible`, but these are not implemented end-to-end.

An allocation starts in `Pending` status, transitions to `Registered` once processed, and can move to `Error` or `Deleting`. The allocation name must be unique per tenant per site.

### Creating a Compute Allocation

Using the TUI (recommended):

```
nicocli tui
> allocation create
```

The TUI prompts in this order:

1. **Site** -- select from discovered sites
2. **Allocation name** -- a unique name for this allocation
3. **Description** -- optional
4. **Tenant** -- select from tenant accounts, your own org (shown as "self"), or enter a UUID manually
5. **Resource type** -- `InstanceType` or `IPBlock`
6. **Instance Type** -- scoped to the selected site so you only see valid types
7. **Constraint type** -- `Reserved`
8. **Constraint value** -- machine count (e.g., 8)

Non-interactive:

```
nicocli allocation create --data-file - <<'EOF'
{
  "name": "acme-gpu-pool",
  "description": "GB200 allocation for Acme Corp",
  "tenantId": "<tenant-uuid>",
  "siteId": "<site-uuid>",
  "allocationConstraints": [
    {
      "resourceType": "InstanceType",
      "resourceTypeId": "<instance-type-uuid>",
      "constraintType": "Reserved",
      "constraintValue": 8
    }
  ]
}
EOF
```

The system validates that enough machines of the specified instance type are available before accepting the allocation.

### Creating a Network Allocation

```
nicocli allocation create --data-file - <<'EOF'
{
  "name": "acme-network",
  "tenantId": "<tenant-uuid>",
  "siteId": "<site-uuid>",
  "allocationConstraints": [
    {
      "resourceType": "IPBlock",
      "resourceTypeId": "<ip-block-uuid>",
      "constraintType": "Reserved",
      "constraintValue": 24
    }
  ]
}
EOF
```

A `constraintValue` of 24 allocates a /24 sub-block (256 addresses). The value must be between 1 and 32 and must be greater than or equal to the parent block's prefix length.

### Listing and Inspecting Allocations

```
nicocli allocation list --output table
nicocli allocation get <allocation-id>
```

`allocation list` supports rich filter flags (verified via `--help`): `--site-id`, `--tenant-id`, `--infrastructure-provider-id`, `--resource-type` (`InstanceType` or `IPBlock`), `--resource-type-id`, `--status`, `--constraint-type`, `--constraint-value`. The `--query` flag is a free-text search over name/description/status, NOT a key-value filter -- use the dedicated flags instead.

```
nicocli allocation list --resource-type InstanceType
nicocli allocation list --site-id <site-uuid> --tenant-id <tenant-uuid>
nicocli allocation list --status Registered --output table
```

TUI equivalents: `allocation list`, `allocation get`. The list-table output prints a one-line pagination summary on stderr (e.g. `Page 1/18 (5 items, 88 total). Use --all to fetch everything.`); `--all` follows pagination for you.

Example allocation detail (IPBlock allocation, /28 reservation against a /16 pool):

```json
{
  "allocationConstraints": [{
    "ResourceTypeID": "<ip-block-uuid>",
    "allocationId": "<allocation-uuid>",
    "constraintType": "Reserved",
    "constraintValue": 28,
    "derivedResourceId": "<derived-block-uuid>",
    "id": "<constraint-uuid>",
    "ipBlock": {
      "id": "<ip-block-uuid>",
      "name": "site-ipv4-pool",
      "prefix": "10.99.0.0",
      "prefixLength": 16,
      "routingType": "Public",
      "status": "Ready"
    },
    "resourceType": "IPBlock"
  }],
  "id": "<allocation-uuid>",
  "infrastructureProviderId": "<provider-uuid>",
  "name": "acme-network",
  "siteId": "<site-uuid>",
  "status": "Registered",
  "tenantId": "<tenant-uuid>"
}
```

`derivedResourceId` is the ID of the sub-resource carved from the parent (the actual sub-block for IP allocations). `ResourceTypeID` is mixed-case in the response -- field name is what the JSON API returns.

### Modifying Allocation Constraints

Adjust an existing constraint value (e.g., increase a machine quota). Note the flag-first ordering with two positionals:

```
nicocli allocation constraint update --constraint-value 12 <allocation-id> <constraint-id>
```

Or with `--data`:

```
nicocli allocation constraint update --data '{"constraintValue": 12}' <allocation-id> <constraint-id>
```

The system validates:

- **Increases**: Enough machines must be available to support the new total.
- **Decreases**: The new total cannot fall below the tenant's active instance count for that instance type. If the tenant has 6 running instances and you reduce to 4, the request is rejected.

### Deleting an Allocation

```
nicocli allocation delete <allocation-id>
```

Deletion is blocked if the tenant has active instances or subnets consuming resources from the allocation. Terminate dependent resources first.

### Multiple Allocations per Tenant

A tenant can have multiple allocations at the same site with different resource types or instance types. The aggregate compute quota for a given instance type is the sum of all allocation constraints for that type across the tenant's allocations at that site.

### Allocation Workflow Summary

1. **Provision the tenant** -- `nicocli tenant get-current-tenant`
2. **Establish a tenant account** -- Provider admin links provider to tenant org
3. **Discover available resources** -- List sites, instance types, and IP blocks
4. **Create compute allocation(s)** -- One per instance type the tenant needs
5. **Create network allocation(s)** -- One per IP block the tenant needs
6. **Verify** -- List allocations and confirm they reach `Registered` status

## Creating VPCs and Subnets

After allocations are in place, the tenant can create VPCs and subnets within their allocated resource boundaries.

### VPC Creation

A VPC is the logical network container for tenant workloads. It defines the tenant boundary for networking and provides the parent context for subnets and instances.

`nicocli vpc create --help` shows these flags:

| Flag | Required | Notes |
|------|----------|-------|
| `--name` | yes | Unique within the tenant |
| `--site-id` | yes | The site this VPC belongs to |
| `--routing-profile` | no | One of `external`, `internal`, `privileged-internal` (REST API mapping); see core docs for semantics |
| `--network-virtualization-type` | no | `FNN` (production) or `ETHERNET_VIRTUALIZER` (legacy) |
| `--nv-link-logical-partition-id` | no | Attach to a specific NVLink partition (GB200) |
| `--vni` | no | Pin a specific VXLAN Network Identifier |
| `--description` | no | |

Realistic non-interactive form:

```
nicocli vpc create \
  --name acme-prod \
  --site-id <site-uuid> \
  --routing-profile internal \
  --network-virtualization-type FNN
```

TUI flow (prompts in order):

```
nicocli tui
> vpc create
```

1. **Site** -- select the site
2. **VPC name** -- unique name
3. **Description** -- optional

Verify the VPC reaches `Ready` status:

```
nicocli vpc list --output table
```

> **Routing profiles** govern which VPCs can exchange routes with which others. The REST API accepts `external`, `internal`, and `privileged-internal`; the underlying gRPC API supports any profile defined under `fnn.routing_profiles` in the API server config. For details, see [VPC Routing Profiles](../manuals/vpc/vpc_routing_profiles.md). For the full networking architecture (VRFs, VNI pools, BGP, deny prefixes), see [VPC Network Virtualization](../manuals/vpc/vpc_network_virtualization.md).

### Subnet Creation

A subnet is an IP address range within a VPC, carved from an allocated IP block.

`nicocli subnet create --help` shows these flags. Note the flag name `--ipv4block-id` (no separator between `v4` and `block`) and the IPv6 counterpart:

| Flag | Required | Notes |
|------|----------|-------|
| `--name` | yes | |
| `--vpc-id` | yes | Parent VPC |
| `--prefix-length` | yes | 1-32 |
| `--ipv4block-id` | one of v4/v6 required | IP block to carve from |
| `--ipv6block-id` | one of v4/v6 required | IPv6 block to carve from |
| `--description` | no | |

Non-interactive (IPv4):

```
nicocli subnet create \
  --name acme-subnet-1 \
  --vpc-id <vpc-uuid> \
  --ipv4block-id <ip-block-uuid> \
  --prefix-length 28
```

Or via `--data` (the JSON body uses camelCase even though the flag is single-word):

```
nicocli subnet create --data '{"name": "acme-subnet-1", "vpcId": "<vpc-uuid>", "ipv4BlockId": "<ip-block-uuid>", "prefixLength": 28}'
```

TUI flow:

```
nicocli tui
> subnet create
```

1. **VPC** -- select the parent VPC
2. **Subnet name** -- unique name
3. **Description** -- optional
4. **Prefix length** -- 1-32
5. **IPv4 Block** -- scoped to the VPC's site

Verify:

```
nicocli subnet list --output table
```

## Launching an Instance

An instance in NICo is a bare-metal machine assigned to a tenant within a VPC. Creating an instance claims a machine from the tenant's compute allocation, associates it with a VPC, and triggers the provisioning workflow (OS installation, network configuration, security lockdown).

`nicocli instance create --help` shows these flags:

| Flag | Required | Notes |
|------|----------|-------|
| `--name` | yes | |
| `--tenant-id` | yes | Owning tenant -- often missed in older docs |
| `--vpc-id` | yes | Parent VPC |
| `--machine-id` | no | Pin to a specific machine (requires `targetedInstanceCreation: true` on the tenant) |
| `--instance-type-id` | no | Pick from the pool of machines of this type (alternative to `--machine-id`) |
| `--operating-system-id` | no | OS for PXE provisioning |
| `--allow-unhealthy-machine` | no | Override health checks |
| `--ipxe-script` | no | Custom iPXE script |
| `--user-data` | no | cloud-init style user data |
| `--phone-home-enabled` | no | Whether to wait for the OS to phone home for `BootCompleted` |
| `--network-security-group-id` | no | NSG to apply |

`interfaces[]` and `sshKeyGroupIds[]` are array-typed and must go through `--data` / `--data-file`.

Non-interactive form (with one interface and one SSH key group):

```
nicocli instance create --data-file - <<'EOF'
{
  "name": "acme-worker-01",
  "tenantId": "<tenant-uuid>",
  "vpcId": "<vpc-uuid>",
  "instanceTypeId": "<instance-type-uuid>",
  "interfaces": [
    {"vpcPrefixId": "<vpc-prefix-uuid>"}
  ],
  "sshKeyGroupIds": ["<ssh-key-group-uuid>"]
}
EOF
```

If you want to target a specific machine instead, replace `instanceTypeId` with `machineId`. Machine targeting requires the tenant to have `capabilities.targetedInstanceCreation: true`.

TUI flow:

```
nicocli tui
> instance create
```

1. **VPC** -- select the target VPC
2. **Machine** -- select from machines in `Ready` state at the VPC's site
3. **Instance name** -- unique name
4. **Operating system** -- optional
5. **VPC prefix** -- network prefix for each interface (loops, can add more)
6. **SSH key groups** -- optional, attaches SSH keys for serial-console access

### Verifying an Instance Is Running

After creation, the instance goes through these states:

```
Pending -> Ready -> BootCompleted          (initial provisioning, OS up + phone-home)
Pending -> Ready                            (initial provisioning, no phone-home)
Ready -> Configuring -> Ready               (in-place reconfigure: NSG, SSH keys, OS, iPXE, user-data)
Ready -> Rebooting -> Ready -> BootCompleted (during reboot)
Error                                       (if provisioning fails)
```

Two states are easy to miss:

- `BootCompleted` -- follows `Ready` once the OS phones home. Instances without phone-home enabled stop at `Ready`.
- `Configuring` -- the instance transitions through this state when its config is being updated in place (e.g. attaching a new Network Security Group, rotating SSH key groups, swapping the OS image, or pushing new user-data). Configuring does NOT trigger a reboot on its own; the instance returns to `Ready` once the change is applied. A reboot caused by `--trigger-reboot=true` goes through `Rebooting`, not `Configuring`.

Monitor progress:

```
nicocli instance list --output table
nicocli instance get <instance-id>
nicocli instance status-history <instance-id>
```

The instance detail response is rich -- it includes `interfaces[]` with assigned IP addresses and VPC prefix info, `ipxeScript` showing the live boot script, `serialConsoleUrl` for console access, full machine and SKU metadata, and any active `deprecations[]` warnings. The API uses inline `deprecations[]` arrays to flag fields scheduled for removal -- watch for these in your responses.

### Batch Instance Creation

For creating multiple identical instances at once, use `instance batch-create`. Unlike `create`, batch-create takes a single shared spec plus a count -- it provisions N instances with auto-generated names from the same instance type, tenant, and VPC. `nicocli instance batch-create --help` shows:

| Flag | Required | Notes |
|------|----------|-------|
| `--name-prefix` | yes | Prefix used to generate per-instance names |
| `--count` | yes | Number of instances to create |
| `--instance-type-id` | yes | Shared across all instances in the batch (machine targeting is not available in batch mode) |
| `--tenant-id` | yes | Owning tenant |
| `--vpc-id` | yes | Parent VPC |
| `--operating-system-id` | no | OS for PXE provisioning |
| `--topology-optimized` | no | Hint to schedule the batch close together on the fabric |
| `--phone-home-enabled`, `--ipxe-script`, `--user-data`, `--network-security-group-id`, `--description`, `--always-boot-with-custom-ipxe` | no | Same semantics as `instance create` |

Non-interactive form:

```
nicocli instance batch-create \
  --tenant-id <tenant-uuid> \
  --vpc-id <vpc-uuid> \
  --instance-type-id <instance-type-uuid> \
  --name-prefix acme-worker \
  --count 4 \
  --topology-optimized=true
```

`interfaces[]` and `sshKeyGroupIds[]` are still array-typed and must go through `--data` / `--data-file` if you need to attach them at create time.

For batches where each instance needs a different machine ID, OS, or interface set, call `instance create` in a loop instead -- batch-create only handles the homogeneous case.

## Instance Power Management

NICo provides instance-level power management through the REST API. These operations send commands to the underlying BMC via Redfish.

### Rebooting an Instance

`nicocli instance update --help` exposes individual flags for every common operation -- prefer them over `--data`:

| Flag | Effect |
|------|--------|
| `--trigger-reboot=true` | Issue a reboot via BMC |
| `--reboot-with-custom-ipxe=true` | One-time iPXE boot override (for re-provisioning) |
| `--apply-updates-on-reboot=true` | Apply queued firmware/config updates as part of the reboot |
| `--always-boot-with-custom-ipxe=true` | Persist custom iPXE on every boot |
| `--name=<new>` | Rename the instance |
| `--description=<text>` | Update description |
| `--operating-system-id=<uuid>` | Change OS |
| `--ipxe-script=<text>` | Set a custom iPXE script body |
| `--user-data=<text>` | Update cloud-init user-data |
| `--phone-home-enabled=<bool>` | Toggle BootCompleted tracking |
| `--network-security-group-id=<uuid>` | Apply or change NSG |

Reboot:

```
nicocli instance update --trigger-reboot=true <instance-id>
```

Reboot with re-provisioning iPXE and pending updates:

```
nicocli instance update --trigger-reboot=true --reboot-with-custom-ipxe=true --apply-updates-on-reboot=true <instance-id>
```

TUI:

```
nicocli tui
> instance reboot
```

The TUI prompts for instance, custom-iPXE flag, apply-updates flag, and a confirmation.

### Renaming or Updating an Instance

```
nicocli instance update --name acme-worker-01-renamed <instance-id>
nicocli instance update --description "production worker" <instance-id>
```

`sshKeyGroupIds[]` is an array, so changes go through the body:

```
nicocli instance update --data '{"sshKeyGroupIds": ["<group-uuid-1>", "<group-uuid-2>"]}' <instance-id>
```

### Deleting (Terminating) an Instance

```
nicocli instance delete <instance-id>
```

In TUI mode, `instance delete` prompts for confirmation before proceeding. Deletion triggers the full sanitization workflow: secure erase of NVMe storage, GPU and system memory wipe, TPM reset, re-attestation, and network isolation teardown. The machine returns to the available pool once sanitization completes.

### Machine-Level Emergency Operations (gRPC Only)

For stuck or unresponsive machines that cannot be managed through the instance API, carbide-admin-cli provides direct BMC operations:

```
# Force-reboot via BMC
carbide-admin-cli -c <core-api-url> machine reboot --machine-id="<machine-id>"

# Force-delete a stuck machine (destructive -- wipes machine state)
carbide-admin-cli -c <core-api-url> machine force-delete --machine="<machine-id>"
```

See the [Machine Reboot](../playbooks/machine_reboot.md) and [Force Delete](../playbooks/force_delete.md) playbooks in the core documentation for detailed procedures.

## Tenant Lifecycle Operations

### Viewing the Current Tenant

```
nicocli tenant get-current-tenant
```

For provider admins needing visibility across tenants, list tenant accounts (a filter flag is required):

```
nicocli tenant-account list --infrastructure-provider-id <provider-uuid> --output table
```

### Monitoring Tenant Health

```
nicocli tenant get-current-tenant-stats
```

Non-zero `error` counts warrant investigation:

```
nicocli instance list --status error --output table
```

Provider admins can get cross-tenant compute allocation stats at a site. `instance-type-stats` is a sub-resource of `tenant`, with a `stats` leaf action -- the full command has three tokens:

```
nicocli tenant instance-type-stats stats --site-id <site-uuid>
```

A bare `nicocli tenant instance-type-stats --site-id <id>` returns `flag provided but not defined: -site-id` -- the trailing `stats` is required.

### Disabling a Tenant

NICo has no first-class "disable" operation. Options:

- **Revoke identity provider roles**: Remove `TENANT_ADMIN` from all users. Existing resources remain but cannot be managed.
- **Remove allocations**: Delete all allocations. Existing instances continue running but no new ones can be created.
- **Delete the tenant account**: Sever the provider-tenant relationship entirely (requires all allocations deleted first).

### Tenant Teardown Sequence

There is no `DELETE /tenant` endpoint -- tenant records are permanent. To fully decommission:

1. **Terminate all instances** -- delete every instance; each must reach `Terminated` status.
2. **Delete all subnets** -- remove subnets from every VPC.
3. **Delete all VPCs** -- remove the tenant's VPCs.
4. **Delete all allocations** -- provider admin removes compute and network allocations.
5. **Delete the tenant account** -- provider admin severs the link.
6. **Revoke identity provider access** -- remove roles and optionally org membership.

After this sequence, the tenant record still exists but is inert.

> This teardown is destructive and irreversible at the resource level. Terminated instances cannot be recovered. Always confirm with the tenant team before beginning.

## End-to-End Walkthrough

This section ties together the full Day One workflow. The TUI flow is the recommended path for first-time operators -- it scopes lookups (instance types to sites, VPC prefixes to VPCs, etc.) and you can't easily get the order wrong.

### Step 1: Provision the Tenant (Tenant Admin)

```
nicocli tenant get-current-tenant
```

Idempotent -- creates the tenant lazily on first call.

### Step 2: Establish Tenant Account (Provider Admin)

```
nicocli tenant-account create --infrastructure-provider-id <provider-uuid> --tenant-org <tenant-org>
```

Or via TUI: `tenant-account create`.

### Step 3: Accept Tenant Account (Tenant Admin)

```
# Find the invitation
nicocli tenant-account list --tenant-id <tenant-uuid>

# Accept it
nicocli tenant-account update --data '{}' <account-id>
```

### Step 4: Create Compute Allocation (Provider Admin)

Use the TUI for the first one -- it filters instance types by the selected site and validates capacity:

```
nicocli tui
> allocation create
# Site -> name -> tenant -> InstanceType -> select type -> Reserved -> machine count
```

### Step 5: Create Network Allocation (Provider Admin)

```
nicocli tui
> allocation create
# Same site -> name -> tenant -> IPBlock -> select block -> Reserved -> prefix length
```

### Step 6: Verify Allocations

```
nicocli allocation list --output table --tenant-id <tenant-uuid>
```

All allocations should show `Registered` status.

### Step 7: Create a VPC (Tenant Admin)

```
nicocli vpc create --name <n> --site-id <site-uuid> --routing-profile internal
```

### Step 8: Create a Subnet (Tenant Admin)

```
nicocli subnet create --name <n> --vpc-id <vpc-uuid> --ipv4block-id <ip-block-uuid> --prefix-length 28
```

### Step 9: Launch an Instance (Tenant Admin)

The first instance is easiest via TUI because `interfaces[]` is array-typed:

```
nicocli tui
> instance create
# VPC -> Machine -> name -> OS (optional) -> VPC prefix -> SSH key groups (optional)
```

For automation, use `--data-file` -- see the Launching an Instance section above.

### Step 10: Verify

```
nicocli tenant get-current-tenant-stats
nicocli instance list --output table
nicocli instance status-history <instance-id>
```

The instance should reach `Ready` (or `BootCompleted` if `phoneHomeEnabled: true`). Tenant stats should now show non-zero counts for `instance`, `vpc`, and `subnet`.

## Troubleshooting

### Common Issues

| Symptom | Cause | Resolution |
|---------|-------|-----------|
| HTTP 404 "The requested path could not be found" on every command | `api.name` in your config does not match the deployment | See the nicocli reference guide for how to find the deployment's expected `api.name` and update your config |
| HTTP 401 "Request is missing authorization header" | No bearer token cached | Run `nicocli login` (or for SSA deployments, run your token-fetch script and set `auth.token` / `auth.token_command`) |
| HTTP 401 on previously-working session | Token expired | If using OIDC or token-command, nicocli auto-refreshes; if using a static `auth.token`, mint a new token |
| `No help topic for 'get-current-user'` | Command name wrong; CLI generates `user get`, not `user get-current-user` | Use `nicocli user get` |
| `flag(s) --foo placed after a positional argument` | Flags placed AFTER positional args | Move all flags before positionals (`update --name X <id>`, not `update <id> --name X`) |
| HTTP 400 on `tenant-account list` "Either infrastructureProviderId or tenantId..." | Missing required filter | Add `--tenant-id <id>` or `--infrastructure-provider-id <id>` |
| HTTP 403 "Failed to validate membership for org" | User is not a member of the configured org | Verify `api.org` in config matches your IdP org; confirm membership |
| HTTP 403 "User does not have Tenant Admin role" | Missing role assignment | Have an admin in your IdP assign the role |
| HTTP 400 on allocation create "machines available" | Not enough capacity at the site | Check `nicocli instance-type get <id>` for `allocationStats.maxAllocatable` |
| HTTP 400 on allocation constraint update with shrink | New value < tenant's active instance count for that type | Terminate instances first, then resize |
| Instance stuck in `Pending` or `Registering` | Provisioning workflow blocked or failed | `nicocli instance status-history <id>` for the failure message |
| Connection refused on `localhost:8388` | Port-forward died | Re-run `kubectl port-forward -n carbide-rest svc/carbide-rest-api 8388:http` (note the service port name is `http`, not 8388) |

### Debugging with nicocli

Use `--debug` on any command to see the full HTTP request and response. The token is redacted in the log; the path-rewriting from `nico` to whatever `api.name` is set to is visible. Real output:

```
$ nicocli --debug tenant get-current-tenant
time=... msg="API request: GET http://<api>/v2/org/<org>/<api-name>/tenant/current"
time=... msg="Request headers: {\"Accept\":[\"application/json\"],\"Authorization\":[\"Bearer <redacted>\"]}"
time=... msg="API response: ... -> 200 OK"
time=... msg="Response body: {...}"
```

### Version mismatch is normal

The CLI version and the API server version are independent. CLI is generated from the OpenAPI spec at the time of build; the server reports its own image version (visible in audit response `apiVersion` field). Different versions are expected -- the wire protocol is stable enough that mismatches rarely matter.

### Audit log

The list view is intentionally lightweight -- each entry has `id`, `endpoint`, `method`, `statusCode`, `userId`, `clientIP`, `apiVersion`, and `timestamp`. To see the full request, including the request body and the resolved user object, fetch a single entry:

```
nicocli audit list --output json --page-size 5      # find entries of interest
nicocli audit get <audit-id>                         # fetch full detail
```

`audit get` adds `body`, `queryParams`, `extraData`, `durationMs`, `statusMessage`, and the resolved `user` (with email and name when the caller was a human, blanks when the caller was a service account). The table form of `audit list` only shows `id` -- always use `--output json` (or `audit get`) for anything more than ID discovery.

### Using the TUI for Exploration

The TUI is the recommended tool for exploratory work. It handles config selection, authentication, and provides tab-complete interactive commands:

```
nicocli tui
```

The TUI discovers all `config*.yaml` files in `~/.nico/` and lets you pick an environment at startup. Commands like `allocation create` scope lookups to the relevant site automatically, reducing the chance of selecting a resource from the wrong site.

## Quick Reference

Flag-first ordering -- always put flags before positional args.

| Operation | Command | Role Required |
|-----------|---------|--------------|
| View current user | `nicocli user get` | Any authenticated user |
| View current tenant | `nicocli tenant get-current-tenant` | Tenant Admin |
| View tenant stats | `nicocli tenant get-current-tenant-stats` | Tenant Admin |
| Service-account status | `nicocli service-account get` | Any authenticated user |
| List tenant accounts | `nicocli tenant-account list --tenant-id <id>` (or `--infrastructure-provider-id`) | Provider or Tenant Admin |
| Create tenant account | `nicocli tenant-account create --infrastructure-provider-id <id> --tenant-org <org>` | Provider Admin |
| Accept tenant account | `nicocli tenant-account update --data '{}' <account-id>` | Tenant Admin |
| Delete tenant account | `nicocli tenant-account delete <account-id>` | Provider Admin |
| Cross-tenant stats | `nicocli tenant instance-type-stats stats --site-id <id>` | Provider Admin |
| List allocations (filter) | `nicocli allocation list --resource-type InstanceType --site-id <id>` | Provider or Tenant Admin |
| Create allocation | `nicocli allocation create --data-file <file>` (constraints are array-typed) | Provider Admin |
| Update constraint | `nicocli allocation constraint update --constraint-value N <alloc-id> <constraint-id>` | Provider Admin |
| Delete allocation | `nicocli allocation delete <alloc-id>` | Provider Admin |
| List instance types | `nicocli instance-type list` | Provider or Tenant Admin |
| Create VPC | `nicocli vpc create --name <n> --site-id <id> --routing-profile internal` | Tenant Admin |
| Create subnet | `nicocli subnet create --name <n> --vpc-id <id> --ipv4block-id <id> --prefix-length 28` | Tenant Admin |
| Create instance | `nicocli instance create --data-file <file>` (interfaces are array-typed) | Tenant Admin |
| Reboot instance | `nicocli instance update --trigger-reboot=true <instance-id>` | Tenant Admin |
| Rename instance | `nicocli instance update --name <new> <instance-id>` | Tenant Admin |
| Delete instance | `nicocli instance delete <instance-id>` | Tenant Admin |
| Audit log | `nicocli audit list --output json --page-size 50` | Provider or Tenant Admin |

## Related Documentation

- [Network Isolation](network-isolation.md) -- Per-plane tenant isolation (Ethernet, InfiniBand, NVLink)
- [Organization & Permissions](org-permissions.md) -- IdP-managed roles and user setup
- [Quick Start Guide](../getting-started/quick-start.md) -- NICo deployment and Day Zero walkthrough
- [VPC Routing Profiles](../manuals/vpc/vpc_routing_profiles.md) -- Profile configuration and behavior
- [VPC Network Virtualization](../manuals/vpc/vpc_network_virtualization.md) -- Full networking architecture
- [VPC Peering](../manuals/vpc/vpc_peering_management.md) -- Connecting VPCs (gRPC only)
- [NVLink Partitioning](../manuals/nvlink_partitioning.md) -- NVLink domain management
- [Machine Reboot Playbook](../playbooks/machine_reboot.md) -- Emergency BMC reboot procedures
- [Force Delete Playbook](../playbooks/force_delete.md) -- Removing stuck machines
- [Day 0/1/2 Lifecycle](../overview/lifecycle.md) -- NICo lifecycle model overview
