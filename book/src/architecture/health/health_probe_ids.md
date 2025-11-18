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

## Site Explorer health probe identifiers

### `BmcExplorationFailure`

Indicates that the hosts BMC endpoint could not be scraped. This can happen if the BMC is not reachable, but also in case the BMC response to any API call is malformed.

### `PoweredOff`

Indicates that the power status of a host as reported by the BMC is **not** on.

## Hardware/BMC health probe identifiers

### `Thermal`

Indicates that the overall thermal subsystem (fans & temperature sensors) of the BMC reports an abnormal value.

### `Power`

Indicates that the overall power subsystem (power supplies, voltages, etc) of the BMC reports an abnormal value.

### `Voltage`

Indicates that a voltage is out of range according to the BMC

### `Temperature`

Indicates that a temperature is out of range according to the BMC

### `FanSpeed`

Indicates that a fan speed is out of range according to the BMC

### `PowerSupply`

Indicates a power supply problem reported by the BMC

### `PoweredOff`

Indicates that the host is powered off according to the BMC

### `Leak`

Indicates a leak reported according to the BMC


## DPU related health probe identifiers

### `BgpPeeringTor`

Indicates that a BGP session with a top-of-rack (TOR) switch could not be established by a host/DPU.

### `BgpPeeringRouteServer`

Indicates that a BGP session with the route server that is part of the part of the Carbide control plane could not be established by a host/DPU.

### `HeartbeatTimeout`

Indicates that there was no communication between `dpu-agent` and `carbide-core` for a certain amount of time.
This condition usually implies that the DPU won't be able to apply any configuration changes.

### `StaleAgentVersion`

Indicates that `dpu-agent` has not been updated to the newest version, even though the newest release had been available for a certain amount of time.

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
