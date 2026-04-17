# VPC Routing Profiles

This page describes how to create VPCs based on the routing profile configuration of the site. Routing profile configuration is part of the required baseline server configuration for successful VPC creation.

This page is intended for engineers who are responsible for configuring or operating a production API server.

## Core Concepts

### VPC

A VPC is the logical network container used for tenant workloads. It defines the tenant boundary for networking behavior and provides the parent context for related resources such as prefixes and segments.

### Network Virtualization Type

A VPC has a `network_virtualization_type` that determines how the platform implements networking for that VPC. There are two supported values:

- `FNN`: The production networking model
- `ETHERNET_VIRTUALIZER`: A legacy, deprecated, and not officially supported model. It may still appear in existing objects or older workflows, but it should not be treated as the target model for production planning.

> **Important**: If no virtualization type is supplied when a VPC is created, the API currently defaults the VPC to `ETHERNET_VIRTUALIZER`. This default should be understood as compatibility behavior, not as a production recommendation. The `FNN` option should always be specified for VPCs on a production site.

### Routing Profile Type

A VPC also has a `routing_profile_type`, which determines the routing policy class associated with that VPC. Supported profile types include the following:

- `EXTERNAL`
- `INTERNAL`
- `MAINTENANCE`
- `PRIVILEGED_INTERNAL`

This setting determines which routing behavior the VPC is expected to follow.

### API Server Routing Profiles

The API server must define the available routing profiles under the `fnn.routing_profiles` section of the configuration file.

Each entry is keyed by the routing profile name and contains the site-specific routing behavior associated with that profile. This includes whether the profile is treated as internal or external and which route-policy settings apply.

## Relationship between network_virtualization_type and routing_profile_type

The `network_virtualization_type` and `routing_profile_type` settings are related, but they serve different purposes.

- The `network_virtualization_type` determines how the VPC is implemented (i.e. it selects the networking model).
- The `routing_profile_type` determines which routing policy the VPC uses.
- The API server `fnn.routing_profiles` configuration defines what each routing profile means at that site.

## How the API Selects a VPC Routing Profile

When a VPC is created, the API determines the routing profile as follows:

1. If the create request includes `routing_profile_type`, that value is used.
2. If the request does not include `routing_profile_type`, the API uses the tenant’s `routing_profile_type`.
3. The API then looks for a routing profile with the same name in `fnn.routing_profiles`.

The API also enforces privilege boundaries. A VPC cannot request a routing profile that is more privileged than the tenant’s allowed routing profile. For example, a tenant that is limited to `EXTERNAL` cannot create an `INTERNAL` VPC.

## Why Routing Profile Configuration Is Required in Production

Routing profile resolution is part of standard production-site VPC creation. The API uses the selected routing profile during VPC setup, including VNI allocation behavior. As a result, a production site must define the routing profiles that tenants and VPCs are expected to use.

Even if a site has legacy objects that use `ETHERNET_VIRTUALIZER`, production operations should still be planned around the `FNN` routing-profile model. The presence of the legacy virtualization type does not remove the need for correct FNN routing profile configuration.

## Required API Server Configuration

At a minimum, the API server should define every routing profile type that may be assigned to a tenant or used by a VPC.

A representative TOML example is shown below:

```toml
[fnn]

[fnn.routing_profiles.EXTERNAL]
internal = false
route_target_imports = []
route_targets_on_exports = []
leak_default_route_from_underlay = false
leak_tenant_host_routes_to_underlay = false

[fnn.routing_profiles.INTERNAL]
internal = true
route_target_imports = []
route_targets_on_exports = []
leak_default_route_from_underlay = false
leak_tenant_host_routes_to_underlay = false
```

If the site needs to support additional routing profile types, they should also be defined explicitly:

```toml
[fnn]

[fnn.routing_profiles.EXTERNAL]
internal = false
route_target_imports = []
route_targets_on_exports = []
leak_default_route_from_underlay = false
leak_tenant_host_routes_to_underlay = false

[fnn.routing_profiles.INTERNAL]
internal = true
route_target_imports = []
route_targets_on_exports = []
leak_default_route_from_underlay = false
leak_tenant_host_routes_to_underlay = false

[fnn.routing_profiles.MAINTENANCE]
internal = true
route_target_imports = []
route_targets_on_exports = []
leak_default_route_from_underlay = false
leak_tenant_host_routes_to_underlay = false

[fnn.routing_profiles.PRIVILEGED_INTERNAL]
internal = true
route_target_imports = []
route_targets_on_exports = []
leak_default_route_from_underlay = false
leak_tenant_host_routes_to_underlay = false
```

The exact route-target values and leak settings are site-specific, but the profile names must exist and must match the API values exactly.

## How Tenant Routing Profiles Affect VPC Creation

Each tenant may have a `routing_profile_type`. In a production site, this serves as the default routing profile for VPCs created under that tenant. This has two important consequences:

- If a VPC creation request does not specify `routing_profile_type`, the tenant's routing profile is used automatically.
- If the tenant is configured with a profile that is not present in `fnn.routing_profiles`, VPC creation will fail.

For this reason, tenant configuration and API server routing profile configuration must be managed together.

## Changing a Tenant’s Routing Profile

A tenant's routing profile can only be changed if *the tenant has no active VPCs*. Otherwise, the API server rejects the update.

This restriction exists because VPC behavior depends on the tenant's permitted routing profile, and changing the tenant's profile while VPCs already exist could invalidate assumptions made when those VPCs were created.

### Process for Changing a Tenant's Routing Profile

The following is a safe operational sequence for changing a tenant's routing profile:

1. Confirm that the destination routing profile is already defined in `fnn.routing_profiles` on the API server.
2. Verify that the tenant has no active VPCs.
3. Update the tenant's `routing_profile_type`.
4. Create new VPCs for that tenant using the updated profile policy.

If the tenant has active VPCs, those VPCs must be deleted before the tenant profile can be changed.

### Using the admin-cli

The REST API currently creates tenants with a default routing-profile of `EXTERNAL`.

For deployments where this is insufficient, the gRPC admin-cli supports tenant profile updates through the `tenant update` command.

The tenant organization ID is required as a positional argument:

```
admin-cli tenant update <tenant-org> -p <profile>
```

**Examples**

```
admin-cli tenant update example-org -p external
admin-cli tenant update example-org -p internal
admin-cli tenant update example-org -p privileged-internal
admin-cli tenant update example-org -p maintenance
```

The following are supported CLI values:

- `external`
- `internal`
- `privileged-internal`
- `maintenance`

This is the recommended workflow for changing a tenant's routing profile using the admin-cli:

1. Review the current tenant record:

   `admin-cli tenant show <tenant-org>`

2. Confirm that the tenant has no active VPCs.

3. Apply the update:

   ```
   admin-cli tenant update <tenant-org> -p internal
   ```

The CLI also supports an optional version-match flag:

```
admin-cli tenant update <tenant-org> -p internal -v <current-version>
```

This flag is optional. It is not a verbosity setting, but is used for optimistic concurrency checking and causes the update to be rejected if the tenant record has changed since it was last reviewed.

If the tenant still has active VPCs, the command will fail. In this case, the existing VPCs must be removed before the tenant routing profile can be changed.

### Operational implication

This means the tenant routing profile should be treated as a planning decision rather than a casual runtime toggle. It is possible to change, but only when the tenant has been returned to a state with no active VPCs.

## Troubleshooting Example

Consider the following example error returned during VPC creation:

```
routing_profile_type not found: EXTERNAL
```

This error should be interpreted as a routing profile lookup failure during VPC creation.

### What This Means

The API determined that the effective routing profile type of the VPC was `EXTERNAL`. It then attempted to look up a routing profile named `EXTERNAL` in the `fnn.routing_profiles` configuration for the API server. That lookup failed because no matching entry was defined.

### Why This Happens

This commonly occurs in the following situations:

- The tenant's routing profile type is `EXTERNAL`, and the VPC request did not override it.
- The VPC request explicitly requested `EXTERNAL`.
- The API server configuration does not contain `[fnn.routing_profiles.EXTERNAL]`.
- The configuration contains a similar profile, but the key name does not exactly match `EXTERNAL`.

### How to Resolve This Issue

The appropriate resolution is to add the missing routing profile definition to the API server configuration and ensure that the tenant and VPC are using a profile that is intentionally supported by the site.

A minimal TOML example is shown below:

```toml
[fnn]

[fnn.routing_profiles.EXTERNAL]
internal = false
route_target_imports = []
route_targets_on_exports = []
leak_default_route_from_underlay = false
leak_tenant_host_routes_to_underlay = false
```

After adding the profile, also verify the following:

1. The tenant exists.
2. The tenant's `routing_profile_type` is the one you intend to use.
3. The VPC request is either inheriting the correct tenant profile or explicitly requesting the correct profile.
4. The profile name in the configuration exactly matches the API value.

### Broader Lessons

This example illustrates an important operational rule: In a production site, all routing profile types that may be assigned to tenants or requested by VPCs must already be defined in the API server configuration.

## Additional Troubleshooting Checklist

When investigating VPC creation failures related to routing profiles, the following checks are recommended:

1. Confirm that `FNN` is enabled on the site.
2. Confirm that the required routing profile exists under `fnn.routing_profiles`.
3. Confirm that the profile name is spelled exactly as expected.
4. Check the tenant’s `routing_profile_type`.
5. Check whether the VPC request explicitly supplied the `routing_profile_type`.
6. Confirm that the requested or inherited routing profile is permitted for that tenant.
7. Confirm that the routing profile definitions needed by the site are present before creating or updating tenants and VPCs.