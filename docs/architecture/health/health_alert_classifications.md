## Health alert classifications

NVIDIA Infra Controller (NICo) currently uses and recognizes the following set of health alert classifications by convention:

### `PreventAllocations`

Hosts with this classification can not be used by tenants as instances.
An instance creation request using the hosts Machine ID will fail, unless the targeted instance creation feature is used.

### `PreventHostStateChanges`

Hosts with this classification won't move between certain states during the host's lifecycle.
The classification is mostly used to prevent a host from moving between states while it is uncertain whether all necessary configurations have been applied.

### `SuppressExternalAlerting`

Hosts with this classification will not be taken into account when calculating
site-wide fleet-health. This is achieved by metrics/alerting queries ignoring the amount of hosts with this classification while doing the calculation of 1 - (hosts with alerts / total amount of hosts).

### `ExcludeFromStateMachineSla`

Hosts with this classification will not be counted towards state machine transition time SLA.
This classification is mostly used to prevent the state machine from continuously alerting when some manual operations are being performed on the machine.

It is applied automatically (together with `PreventAllocations` and `SuppressExternalAlerting`) when a host is placed into maintenance mode via the `SetMaintenance` RPC, so that stuck-instance / state-machine SLA alerts do not page on-call for hosts an operator is actively working on — regardless of which state or substate the host is in at the time.

### `StopRebootForAutomaticRecoveryFromStateMachine`

For hosts with this classification, the NICo state machine will not automatically
execute certain recovery actions (like reboots). The classification can be used to prevent NICo from interacting with hosts while datacenter operators manually perform certain actions.

### `Hardware`

Indicates a hardware-related issue and is used as a broad bucket for hardware/BMC alerts.

### `SensorWarning`

Indicates that a sensor reading violated a caution/warning threshold.
In `nico-hardware-health`, this corresponds to crossing `lower_caution`/`upper_caution` thresholds.

### `SensorCritical`

Indicates that a sensor reading violated a critical threshold.
In `nico-hardware-health`, this corresponds to crossing `lower_critical`/`upper_critical` thresholds.

### `SensorFatal`

Indicates that a sensor reading violated a fatal threshold.
In `nico-hardware-health`, this corresponds to crossing `lower_fatal`/`upper_fatal` thresholds.

### `SensorFailure`

Indicates that a sensor reading is outside the advertised valid range.
In `nico-hardware-health`, this corresponds to values outside `range_min`/`range_max` when that range is well-formed.

For `BmcSensor` alerts, severity is evaluated in this order:
`SensorFailure` -> `SensorFatal` -> `SensorCritical` -> `SensorWarning`.
The first rung that matches wins, so a breach never falls through to a lower severity.

Special case for sensor classifications:
if thresholds indicate warning but the BMC explicitly reports sensor health as `Ok`,
the probe is treated as success and no alert classification is emitted. Only `SensorWarning`
is suppressed this way — `SensorCritical`, `SensorFatal` and `SensorFailure` always alert,
so a BMC that reports itself healthy cannot silence independent threshold alerting.

Thresholds and reading ranges are sanitized where they are collected, not where they are
evaluated: a BMC that signals "this bound is not implemented" with an in-band value
(iDRAC 7.20.x reports `-1`) has that bound treated as unset for classification and for the
alert message. The metrics label path is not covered by that guarantee — it renders an
unset `upper_critical`/`lower_critical` as `0`, which is tracked separately.

A sensor with no fatal bounds at all cannot produce `SensorFatal` and tops out at
`SensorCritical`. An unset `upper_fatal` alone does not cap it: `lower_fatal` can still
fire on a low reading, and `SensorFailure` still applies whenever the reading falls outside
a well-formed `range_min`/`range_max`.
