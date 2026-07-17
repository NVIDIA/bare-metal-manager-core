# NVLink Domain Health Reports (Day 2)

Operator guide for managing **NVLink domain health reports**: health information
submitted by external tools or operators against an NVLink domain.

Each report is keyed by a **source** identifier. Multiple merge-mode sources
coexist and contribute to the domain's aggregate health. A replace-mode source
overrides that aggregate. Reports are persisted in the
`nvlink_domain_health_reports` table. See
[health report overrides](../architecture/health_aggregation.md#health-report-overrides)
for the same source-keyed model applied to hosts.

Management surfaces:

- **Admin CLI:** `nico-admin-cli nvl-domain health-report` (below).
- **Admin web UI:** NVLink domain health pages, linked from machine detail.

CLI RPC calls require the `Health` or `ForgeAdminCLI` RBAC permission
scope. Admin web UI access is controlled by its deployment authentication and
network policy.

Background: [Health Aggregation](../architecture/health_aggregation.md) and
[Monitoring and Health](./monitoring-health.md).

---

## Report sources

A **report source** is the identifier of the system or user that submitted a
report (the `HealthReport::source` field, for example, `overrides.sre-team`). Keeping
each external system or operator on a distinct source lets their merge-mode
reports coexist. Submitting a report with an existing source replaces that
source's prior report. `show` lists sources and modes applied to a domain;
`remove` deletes one source's report.

## CLI commands

### List report sources for a domain

```sh
nico-admin-cli nvl-domain health-report show <DOMAIN_ID>
```

Lists health report entries applied to the NVLink domain, including
source, mode, observation time, and alert count.

### Remove a report source

```sh
nico-admin-cli nvl-domain health-report remove <DOMAIN_ID> <REPORT_SOURCE>
```

Removes the report submitted under `<REPORT_SOURCE>` from the domain.

### Print an empty report template

```sh
nico-admin-cli nvl-domain health-report print-empty-template
```

Prints an empty health report template.

## Examples

```sh
# See which sources are reporting on a domain
nico-admin-cli nvl-domain health-report show 12345678-1234-5678-90ab-cdef01234567

# Clear a stale report submitted for maintenance
nico-admin-cli nvl-domain health-report remove 12345678-1234-5678-90ab-cdef01234567 internal-maintenance

# Get a template to build an insert payload
nico-admin-cli nvl-domain health-report print-empty-template
```

## Report format

NVLink domain health reports use the same `HealthReport` / `HealthProbeAlert`
schema as the rest of NICo health. Insertion wraps a report in a
`HealthReportEntry` that selects `Merge` or `Replace` mode. See
[Health Report format](../architecture/health_aggregation.md#health-report-format)
for the field-by-field definition.
