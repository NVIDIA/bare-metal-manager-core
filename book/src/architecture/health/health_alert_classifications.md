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
