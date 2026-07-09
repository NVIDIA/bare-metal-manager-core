# Tenant-Visible Instance Health

## Software Design Document

## Revision History

| Version | Date | Modified By | Description |
| :---: | :---: | :---- | :---- |
| 0.1 | 07/09/2026 | Sunil Kumar | Initial version |
|  |  |  |  |

# **1\. Introduction**

Machine health is currently visible to site administrators, but tenants do not have a tenant-safe way to determine whether the host backing an Instance has a health issue. Tenants need this information for operational workflows such as evacuation, SLURM scheduling decisions, Kubernetes node drain automation, and tools like NVSentinel that consume external node health.

Tenants must not receive the full Machine health report. Some Machine health alerts are internal, operational, or too low-level for tenant action. The tenant-facing surface must expose only the subset of health signals that are explicitly safe and useful for tenants.

## **1.1 Purpose**

The purpose of this document is to define the design for exposing a tenant-safe projection of host health through NICo Instance APIs and the Instance Metadata Service. The document describes the API model, derivation rules, visibility boundary, component responsibilities, security considerations, and compatibility behavior.

## **1.2 Definitions and Acronyms**

| Term/Acronym | Definition |
| :---- | :---- |
| NICo | NVIDIA bare-metal life-cycle management system, also referred to as Bare Metal Manager |
| SDD | Software Design Document |
| API | Application Programming Interface |
| Tenant | A NICo client, org, or account that provisions and manages bare-metal nodes through NICo APIs |
| Site admin | Operator or administrator with access to site-level Machine health and repair workflows |
| Instance | Tenant-facing allocation running on a Machine |
| Machine | Bare-metal host managed by NICo |
| Machine health | Site-admin-facing health report for a Machine |
| Aggregate health | Core-derived Machine health report after combining relevant health report sources |
| IMDS | Instance Metadata Service |
| DPU | Data Processing Unit, also referred to as a SmartNIC |
| gRPC | Remote procedure call API used by NICo Core |
| REST | HTTP API exposed by NICo REST |
| SLURM | Workload manager commonly used for HPC scheduling |

## **1.3 Scope**

This SDD covers the design for exposing tenant-visible host health for an Instance through:

* Instance gRPC API
* Instance REST API
* Instance Metadata Service

The design is limited to a tenant-safe projection of Machine health. It does not expose full Machine health to tenants.

### **1.3.1 Assumptions, Constraints, Dependencies**

* Core already derives aggregate Machine health.
* `HealthProbeAlert.tenant_message` exists and is the intended field for tenant-safe alert text.
* Tenants should receive only alerts that are explicitly approved for tenant visibility.
* Existing API clients must remain compatible.
* The initial design should not require a new database table.
* The projection must be structured enough for automation and schedulers.

# **2\. System Architecture**

## **2.1 High-Level Architecture**

The design adds a tenant-safe health projection to Instance status. Core derives the projection from aggregate Machine health. REST and IMDS forward the same projection to tenant-facing consumers.

```
Machine health reports
        |
        v
Core aggregate Machine health
        |
        | derive tenant-safe projection
        v
InstanceStatus.tenant_health
        |
        +-- Instance gRPC API
        +-- Instance REST API
        +-- Instance Metadata Service /meta-data/health
```

*Figure-1 Tenant-visible health projection flow*

Core is the source of truth for deriving tenant health. This avoids each API surface independently interpreting raw Machine health and keeps the tenant visibility boundary in one place.

## **2.2 Component Breakdown**

| Component | Description |
| :---- | :---- |
| NICo Core | Derives aggregate Machine health, owns `InstanceStatus.tenant_health`, and updates `tenant_health.state` when Instance status is materialized |
| Instance gRPC API | Returns `InstanceStatus.tenant_health` as part of Instance status |
| NICo REST | Exposes the same tenant-safe projection as `tenantHealth` on Instance responses |
| DPU agent / FMDS | Receives Instance metadata from Core and makes tenant health available through IMDS |
| Instance Metadata Service | Serves tenant health at `/meta-data/health` to workloads running on the host |
| Health probe owners | Decide whether a health alert is tenant-visible by setting `tenant_message` |

# **3\. Detailed Design**

There are six operational areas associated with implementing this feature:

1. *Existing system and additive changes*: Shows what each layer already has and what this design adds.
2. *Tenant health projection model*: Defines the structured API contract exposed through Instance status.
3. *Visibility and filtering rules*: Defines which Machine health alerts can be shown to tenants.
4. *State ownership, state derivation, and severity*: Defines who updates tenant health state and how state and severity are computed.
5. *API exposure*: Defines gRPC, REST, and IMDS behavior.
6. *Security and compatibility*: Defines the tenant isolation boundary and backward compatibility expectations.

## **3.1 Existing System and Additive Changes**

This design is an additive projection on top of the existing Machine health and Instance status flows. It does not replace the site-admin Machine health model and does not require tenants to consume raw Machine health.

| Layer | Existing behavior | Added by this design | Notes |
| :---- | :---- | :---- | :---- |
| Health probe reports | Health probes can report alerts as `HealthProbeAlert` entries. `tenant_message` already exists on the alert model. | Treat non-empty `tenant_message` as the tenant-disclosure gate. | Probe owners opt in to tenant visibility by setting a safe `tenant_message`. |
| Core aggregate health | Core already derives aggregate Machine health for site-admin and internal workflows. | Derive a tenant-safe `InstanceTenantHealth` projection from aggregate Machine health. | Raw Machine health remains available only through existing admin surfaces. |
| Core Instance status model | `InstanceStatus` already contains tenant state and subsystem statuses such as network, InfiniBand, NVLink, SPX, and sync state. | Add optional `InstanceStatus.tenant_health`. | The new field is additive and optional. Existing clients remain compatible. |
| Core status derivation | Instance status is derived from Instance config, observations, host state, and health inputs. | Pass aggregate Machine health into Instance status derivation and populate `tenant_health`. | Core owns updates to `tenant_health.state`. REST and IMDS only forward the projection. |
| gRPC API | Instance gRPC responses already return `Instance.status`. | Return `Instance.status.tenant_health` as part of the same response. | No new gRPC method is required for the initial design. |
| REST API | Instance REST responses already expose Instance status and related Instance data. | Add optional `tenantHealth` to Instance responses. | REST should prefer the Core-derived projection and must not expose raw Machine health. |
| DPU agent / FMDS metadata model | Agent/FMDS already receives Instance metadata used by IMDS. | Carry optional tenant health metadata from Instance status. | This keeps IMDS aligned with the Core projection. |
| Instance Metadata Service | IMDS already exposes metadata categories such as user data and identity-related metadata. | Add `/meta-data/health`. | Returns tenant-safe JSON, or `unknown` with no alerts when unavailable. |
| Database | Machine health is already stored or available through existing Machine health flows. | No new database table is required for the initial implementation. | Future persistence, if needed, should persist only the tenant-safe projection for tenant-facing use cases. |
| Tests | Existing tests cover Machine health and Instance metadata behavior. | Add tests for filtering, state derivation, REST projection, and IMDS `/meta-data/health`. | Tests must prove raw messages and hidden alerts are not exposed. |

The main contract change is therefore one new optional projection on Instance status, plus forwarding that projection through REST and IMDS.

## **3.2 Tenant Health Projection Model**

Core adds an optional tenant health projection to `InstanceStatus`.

```proto
message InstanceStatus {
  optional InstanceTenantStatus tenant = 1;
  optional InstanceTenantHealth tenant_health = 2;
}

message InstanceTenantHealth {
  TenantHealthState state = 1;
  repeated InstanceTenantHealthAlert alerts = 2;
}

enum TenantHealthState {
  TENANT_HEALTH_UNKNOWN = 0;
  TENANT_HEALTH_HEALTHY = 1;
  TENANT_HEALTH_DEGRADED = 2;
  TENANT_HEALTH_UNHEALTHY = 3;
}

enum TenantHealthSeverity {
  TENANT_HEALTH_SEVERITY_UNKNOWN = 0;
  TENANT_HEALTH_SEVERITY_INFO = 1;
  TENANT_HEALTH_SEVERITY_WARNING = 2;
  TENANT_HEALTH_SEVERITY_CRITICAL = 3;
}

message InstanceTenantHealthAlert {
  string id = 1;
  string message = 2;
  optional google.protobuf.Timestamp in_alert_since = 3;
  TenantHealthSeverity severity = 4;
}
```

The projection is intentionally separate from generic status details. A structured model gives tenant automation stable fields for health state, alert IDs, severity, and message text.

## **3.3 Visibility and Filtering Rules**

An alert is tenant-visible only when `HealthProbeAlert.tenant_message` is non-empty.

The tenant-facing alert message must be copied from `tenant_message`. It must not use the raw Machine health `message`.

The following Machine health fields must not be exposed to tenants:

* raw `message`
* `target`
* raw classifications
* health report source internals
* repair metadata
* hardware or operator-only diagnostic details

Setting `tenant_message` is an explicit tenant-disclosure decision. Probe owners should only set it for alerts that are safe and actionable for tenants.

## **3.4 State Ownership, State Derivation, and Severity**

Core owns updates to `InstanceStatus.tenant_health`.

The existing tenant lifecycle state, `InstanceStatus.tenant.state`, is not repurposed for host health. Tenant lifecycle state continues to describe whether the Instance is ready, terminating, or otherwise progressing through its lifecycle. This design adds a separate `tenant_health.state` field for host health.

`tenant_health.state` is derived when Core materializes Instance status from the current Instance snapshot and aggregate Machine health. The health aggregation path continues to own Machine health inputs. REST, DPU agent, FMDS, and IMDS do not update tenant health state; they consume and forward the Core-derived projection.

If tenant health is persisted in a future iteration, the writer should still be the Core status or health aggregation owner, and the persisted value should be the tenant-safe projection rather than raw Machine health.

Tenant health state is derived from the tenant-visible alert set and aggregate health freshness.

| State | Derivation |
| :---- | :---- |
| `Unknown` | Aggregate health is missing, stale, or malformed, and there are no tenant-visible alerts |
| `Healthy` | Aggregate health is available and there are no tenant-visible alerts |
| `Degraded` | One or more tenant-visible alerts exist, but none are critical |
| `Unhealthy` | At least one tenant-visible critical alert exists |

Severity is owned by Core and derived internally from Machine health classifications, but the classifications themselves are not exposed. For the initial implementation, probes should not set a separate tenant severity. For example, classifications that prevent allocations, instance deletion, or host state changes can map to `Critical`; tenant-visible alerts with no classification can map to `Info`; other tenant-visible alerts can map to `Warning`.

### **3.4.1 Derivation Examples**

The following example shows how Core filters raw Machine health into tenant health.

| Alert ID | Raw Machine health message | Tenant message | Classifications | Tenant-visible |
| :---- | :---- | :---- | :---- | :---- |
| `IbPortDown` | `mlx5_0 port 1 down on DPU0` | `Host networking health issue detected` | `PreventAllocations` | Yes |
| `FanSpeedLow` | `fan 2 below threshold` | empty | `PreventHostStateChanges` | No |
| `LinkFlap` | `eth0 link flapping` | `Host network is degraded` | none | Yes |

Core exposes only alerts with non-empty `tenant_message`. In this example, `FanSpeedLow` is not exposed even though it has an internal classification, because it has no tenant-safe message.

Core derives tenant severities as follows:

| Alert ID | Tenant message | Severity | Reason |
| :---- | :---- | :---- | :---- |
| `IbPortDown` | `Host networking health issue detected` | `Critical` | Contains `PreventAllocations` |
| `LinkFlap` | `Host network is degraded` | `Info` | No classifications |

Since at least one tenant-visible alert is `Critical`, Core derives:

```json
{
  "state": "Unhealthy",
  "alerts": [
    {
      "id": "IbPortDown",
      "message": "Host networking health issue detected",
      "severity": "Critical"
    },
    {
      "id": "LinkFlap",
      "message": "Host network is degraded",
      "severity": "Info"
    }
  ]
}
```

If aggregate Machine health contains only hidden internal alerts and aggregate health is current, Core derives:

```json
{
  "state": "Healthy",
  "alerts": []
}
```

If aggregate Machine health is missing, stale, or malformed and there are no tenant-visible alerts, Core derives:

```json
{
  "state": "Unknown",
  "alerts": []
}
```

## **3.5 API Exposure**

### **3.5.1 Instance gRPC API**

The Instance gRPC API exposes tenant health through:

```text
Instance.status.tenant_health
```

The field is optional and additive. Existing clients that do not understand the field continue to work.

### **3.5.2 Instance REST API**

NICo REST exposes tenant health as an optional `tenantHealth` field on Instance responses.

```json
{
  "tenantHealth": {
    "state": "Unhealthy",
    "alerts": [
      {
        "id": "IbPortDown",
        "message": "Host networking health issue detected",
        "severity": "Critical",
        "inAlertSince": "2026-07-09T12:00:00Z"
      }
    ]
  }
}
```

REST should consume the tenant-safe projection from Core when available. REST should not independently expose raw Machine health to tenants.

### **3.5.3 Instance Metadata Service**

IMDS exposes tenant health at:

```text
/meta-data/health
```

Example response:

```json
{
  "state": "unhealthy",
  "alerts": [
    {
      "id": "IbPortDown",
      "message": "Host networking health issue detected",
      "severity": "critical"
    }
  ]
}
```

If tenant health is not available, IMDS should return an `unknown` state with an empty alert list.

```json
{
  "state": "unknown",
  "alerts": []
}
```

## **3.6 Data Model and Storage**

The initial implementation does not require a new database table. Tenant health is derived from aggregate Machine health at the time Instance status is built.

If future requirements need history, auditing, or tenant notifications, a separate persisted model can be introduced later. That persistence should store the tenant-safe projection, not raw Machine health, if it is intended for tenant consumption.

## **3.7 Compatibility**

The change is backward-compatible because all new fields are additive and optional.

| Surface | Compatibility behavior |
| :---- | :---- |
| gRPC | Existing clients ignore unknown optional fields |
| REST | Existing clients ignore the optional `tenantHealth` field |
| IMDS | Existing clients are unaffected unless they query `/meta-data/health` |

The design should not change existing Machine health APIs used by site administrators.

## **3.8 Security Considerations**

This design is security-compliant only if the projection boundary is enforced centrally.

Required safeguards:

* Only expose alerts with non-empty `tenant_message`.
* Never expose raw Machine health messages.
* Never expose Machine health targets or raw classifications.
* Treat missing or stale health as `Unknown` rather than implying the host is healthy.
* Add tests proving raw messages and non-tenant-visible alerts are filtered out.

An optional future hardening step is to add a Core-enforced allowlist of tenant-visible probe IDs. This would make `tenant_message` necessary but not sufficient for tenant disclosure.

# **4\. Alternatives Considered**

## **4.1 Use Generic Instance Status Details**

One option is to add tenant health text to an existing generic status details field.

This is not recommended. Generic details are hard for automation to parse, difficult to version, and more likely to accidentally include internal information. Tenant health needs stable fields for state, alert ID, severity, and safe message text.

## **4.2 Expose Full Machine Health to Tenants**

This is not recommended. Machine health can include hardware targets, low-level diagnostic messages, raw classifications, and operator-only repair context. Exposing it would create unnecessary security and support risk.

## **4.3 Derive Tenant Health Independently in REST and IMDS**

This is not recommended. Independent derivation in each surface risks inconsistent tenant behavior and increases the chance that one path exposes raw Machine health incorrectly. Core should derive the projection once and downstream surfaces should forward it.

# **5\. Design Decisions**

The following decisions define the recommended initial implementation.

| Topic | Decision | Rationale |
| :---- | :---- | :---- |
| Tenant-visible alert allowlist | Do not add a separate probe ID allowlist in the initial implementation. A non-empty `tenant_message` is the tenant visibility gate. | `tenant_message` already exists for this purpose and keeps the disclosure decision close to the probe owner. A separate allowlist can be added later if stronger central policy is needed. |
| Severity ownership | Core owns tenant severity mapping. Probes should not set tenant severity in the initial implementation. | Central mapping gives consistent behavior across all APIs and prevents probes from exposing internal classification details. |
| Top-level timestamp | Do not add a top-level `updated_at` field in the initial contract. Keep `in_alert_since` per alert and use `Unknown` when health freshness is missing, stale, or malformed. | Consumers need stable health state first. A top-level observation timestamp can be added later as an optional field if tenant schedulers need freshness metadata. |
| REST list behavior | Include `tenantHealth` on Instance GET and LIST responses when the projection is available. Do not require an include relation for the initial design. | Tenant health is part of tenant-facing Instance status, not an admin-only relation. REST implementations should avoid N+1 loading by consuming the Core projection or using batch loading where needed. |
| Persistence | Do not add a new database table in the initial implementation. | The first requirement is current tenant-visible health. Historical health, audit, or notification workflows can add persistence later using the tenant-safe projection. |
| IMDS unavailable projection behavior | Return `unknown` with an empty alert list when tenant health is unavailable. | This avoids incorrectly reporting a healthy host when health state cannot be evaluated. |

# **6\. Follow-Up Considerations**

These items are not required for the initial implementation, but they can be revisited after tenant consumers start using the API.

* Add a Core-managed allowlist or registry if `tenant_message` alone is not enough policy control.
* Add optional top-level freshness metadata, such as `observed_at`, if tenant schedulers need to reason about health report age.
* Add persistence or notification workflows if tenants need historical health changes or event delivery.
