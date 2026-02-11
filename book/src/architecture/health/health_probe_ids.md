# Health probe IDs

This chapter provides a list of health probes with their ID.
Health reports will contains these IDs in the `alerts` section in case the associated check or validation has failed.

## Machine validation health probe identifiers

### `FailedValidationTest`

Indicates that a certain host validation test failed.
The alert will carry details about which test failed.

### `FailedValidationTestCompletion`

Indicates that the host validation test framework failed to complete scheduling
all specified tests on the host.

## SKU validation health probe identifiers

### `SkuValidation`

An alert with this ID is placed on a host in case the SKU validation workflow failed.
The alert will make the host un-allocatable by tenants.

## Repair workflow integrations related health probe identifiers

### `TenantReportedIssue`

Indicates that a tenant reported an issue with the host while releasing the bare metal instance. The host won't be available for other tenants until the alert is cleared.

### `RequestRepair`

Indicates that a tenant reported an issue with the host while releasing the bare metal instance
and that repair by an external framework is required.

## Site Explorer health probe identifiers

### `BmcExplorationFailure`

Indicates that the hosts BMC endpoint could not be scraped. This can happen if the BMC is not reachable, but also in case the BMC response to any API call is malformed.

### `PoweredOff`

Indicates that the power status of a host as reported by the BMC is **not** on.

### `SerialNumberMismatch`

Indicates that the serial number on a host does not match the serial number in the Expected Machine manifest.

## Hardware/BMC health probe identifiers

`carbide-hardware-health` currently reports sensor-based hardware health with a single probe ID:

### `BMC_Sensor`

Indicates that a BMC sensor reported a warning/critical/failure condition.

Details:
- `target` is set to the BMC sensor ID (for example, a fan/temperature/power sensor name).
- The alert `message` contains the entity type, reading, unit, and threshold ranges used for evaluation.
- Classifications include `Hardware` and (when available) one of `SensorWarning`, `SensorCritical`, or `SensorFailure`.

Status semantics:
- `SensorFailure`:
  the reading is outside the sensor's advertised valid range (`range_min`/`range_max`), if that range is well-formed.
- `SensorCritical`:
  the reading violates critical thresholds (`lower_critical`/`upper_critical`), if those thresholds are well-formed.
- `SensorWarning`:
  the reading violates caution thresholds (`lower_caution`/`upper_caution`), if those thresholds are well-formed.

Evaluation order (highest severity first):
`SensorFailure` -> `SensorCritical` -> `SensorWarning` -> success.

Special case:
if threshold evaluation indicates warning/critical/failure but the BMC explicitly reports the sensor health as `Ok`,
the service treats the probe as success (to avoid false alerts from incorrect threshold metadata).

`message` format:

```text
<entity_type> '<sensor_id>': <status> - reading <value><unit> (<reading_type>), valid range: <range>, caution: <range>, critical: <range>
```

Example:

```text
power_supply 'PSU0_OutputPower': Critical - reading 1320.00W (power), valid range: 0.0 to 1500.0, caution: 1200.0 to 1300.0, critical: 0.0 to 1310.0
```

## DPU related health probe identifiers

### `BgpPeeringTor`

Indicates that a BGP session with a top-of-rack (TOR) switch could not be established by a host/DPU.

### `BgpPeeringRouteServer`

Indicates that a BGP session with the route server that is part of the part of the Carbide control plane could not be established by a host/DPU.

### `BgpStats`

Indicates that BGP statistics could not be extacted by `dpu-agent`

### `BgpDaemonEnabled`

Indicates that the BGP daemon (FRR) is not running on the DPU

### `DhcpRelay`

Indicates issues regarding the start of the DHCP relay on the DPU

### `DhcpServer`

Indicates issues regarding the start of the DHCP server on the DPU

### `HeartbeatTimeout`

Indicates that there was no communication between `dpu-agent` and `carbide-core` for a certain amount of time.
This condition usually implies that the DPU won't be able to apply any configuration changes.

### `StaleAgentVersion`

Indicates that `dpu-agent` has not been updated to the newest version, even though the newest release had been available for a certain amount of time.

### `ContainerExists`

Indicates that a container that was expected to run on the DPU is not running

### `SupervisorctlStatus`

Indicates an issue with retrieving the list of running services

### `ServiceRunning`

Indicates that an expected service on the DPU is not runnning

### `PostConfigCheckWait`

The alert is placed on a host for a few seconds after a configuration change by dpu-agent in order to allow the configuration changes to "settle" before doing the health assessment.
That avoids the host to move between states even though the new configuration might be  problematic.

### `RestrictedMode`

Indicates that the DPU is not running in restricted mode

### `DpuDiskUtilizationCheck`

Indicates that the dpu-agent failed to check disk utilization

### `DpuDiskUtilizationCritical`

Indicates that the dpu-agent disk utilization on the DPU is above a critical threshold

## Other health probe identifiers

### `MissingReport`

The alert indicates that no health report was received, where health report
was expected. It is different from `HeartbeatTimeout` in the following sense
- `HeartbeatTimeout` alerts can be emitted if data is available, but stale.
  `MissingReport` is only emitted if data has never been received.
- `MissingReport` is mainly used on the carbide client side. It has no impact on
  state changes.

### `MalformedReport`

An alert which can be generated if a HealthReport can not be parsed
This alert is only be used the carbide client side if failing to render the health
report is preferrable to failing the workflow.

### `Maintenance`

The alert is used by site admins to mark hosts that are under maintenance - e.g. for CPU or memory replacements.

### `HostUpdateInProgress`

Indicates that an update for host firmware was scheduled on the host

### `IbCleanupPending`

Indicates that the host was released back to the admin pool without the system being able to fully clean up all port to partition key associations for all InfiniBand interfaces.
This means the host might still be bound to a tenants partition.
Once the IB subsystem can communicate with UFM and detects that the port is not bound to a partition anymore, the alert will automatically clear.
