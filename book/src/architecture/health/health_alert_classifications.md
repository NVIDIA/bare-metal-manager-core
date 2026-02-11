## Health alert classifications

Carbide does currently use and recognize the following set of health alert classifications by convention:

### `PreventAllocations`

Hosts with this classification can not be used by tenants as instances.
An instance creation request using the hosts Machine ID will fail, unless the targeted instance creation feature is used.

### `PreventHostStateChanges`

Hosts with this classification won't move between certain states during the hosts lifecycle.
The classification is mostly used to prevent a host from moving between states while it is uncertain whether all necessary configurations have been applied.

### `SuppressExternalAlerting`

Hosts with this classification will not be taken into account when calculating
site-wide fleet-health. This is achieved by metrics/alerting queries ignoring the amount of hosts with this classification while doing the calculation of 1 - (hosts with alerts / total amount of hosts).

### `StopRebootForAutomaticRecoveryFromStateMachine`

For hosts with this classification, the Carbide state machine will not automatically
execute certain recovery actions (like reboots). The classification can be used to prevent Carbide from interacting with hosts while datacenter operators manually perform certain actions.

### `Hardware`

Indicates a hardware-related issue and is used as a broad bucket for hardware/BMC alerts.

### `SensorWarning`

Indicates that a sensor reading violated a caution/warning threshold.
In `carbide-hardware-health`, this corresponds to crossing `lower_caution`/`upper_caution` thresholds.

### `SensorCritical`

Indicates that a sensor reading violated a critical threshold.
In `carbide-hardware-health`, this corresponds to crossing `lower_critical`/`upper_critical` thresholds.

### `SensorFailure`

Indicates that a sensor reading is outside the advertised valid range.
In `carbide-hardware-health`, this corresponds to values outside `range_min`/`range_max` when that range is well-formed.

For `BmcSensor` alerts, severity is evaluated in this order:
`SensorFailure` -> `SensorCritical` -> `SensorWarning`.

Special case for sensor classifications:
if thresholds indicate warning/critical/failure but the BMC explicitly reports sensor health as `Ok`,
the probe is treated as success and no alert classification is emitted.
