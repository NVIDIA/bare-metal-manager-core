# Leak Detection, Health, and Allocation Protection

## Overview

NICo evaluates leak-related conditions from compute-tray sensor health and BMS leak events. It turns active conditions into health signals and, where configured, allocation protection.

BMS owns the physical leak sensors and remediation actions. NICo provides the infrastructure-management health and allocation-protection surface.

## Current capability

### Compute-tray sensor health

NICo hardware-health monitoring discovers configured BMC endpoints and queries them through Redfish. When compute-tray BMCs expose leak-related sensor data and the relevant health collector is configured, NICo considers that data as part of hardware health.

```text
Compute-tray leak sensor
        ↓
Compute-tray BMC
        ↓ Redfish
NICo hardware-health service
        ↓
NICo hardware health
        ↓
Aggregate host health
```

The alert classification and operational effect for this path depend on the site's health-processor configuration.

### BMS leak-event integration

NICo also supports a BMS event path through `nico-dsx-exchange-consumer`.

```text
BMS detects or clears a leak condition
        ↓
BMS publishes MQTT metadata and value events
        ↓
NICo DSX Exchange consumer
        ↓
NICo rack health report
        ↓
Aggregate host health and allocation protection
```

The consumer supports these BMS event types:

- Rack leak detection (`LeakDetectRack`)
- Rack leak-sensor fault (`LeakSensorFaultRack`)
- Rack-tray leak detection (`LeakDetectRackTray`)

For an active supported BMS event, NICo creates a rack health alert with these classifications:

- `PreventAllocations`
- `SensorCritical`
- `Hardware`

`PreventAllocations` blocks new allocations for hosts affected by the active rack-health condition. When BMS publishes a clear event, NICo removes the corresponding rack health report. NICo then recalculates aggregate health; allocation eligibility can recover when no other active health condition prevents allocation.

## Deployment requirements for BMS event integration

The BMS event path is not enabled automatically in every NICo deployment. To use it, a deployment must have all of the following:

1. `nico-dsx-exchange-consumer` enabled. This Helm subchart is disabled by default.
2. Connectivity and configuration for the BMS MQTT broker and event topics.
3. BMS metadata and value events that use supported point types and identify the affected rack.
4. The consumer configured to call the NICo API.
5. Health aggregation configured for the relevant racks and hosts.

Without these prerequisites, BMS events do not create NICo rack health reports.

## Operational meaning

NICo provides **health visibility and allocation protection** for leak-related conditions. The current BMS event workflow creates a rack health alert that propagates through NICo health aggregation, while BMS handles physical remediation.

Current operational visibility is provided through NICo's health data, health alert details, logs, and metrics.

## Next phase: API-based leak workflows

The next phase follows [issue #5018](https://github.com/NVIDIA/infra-controller/issues/5018) by adding API-based workflows for rack and tray leak detection and leak-handling state. It builds on the current health and allocation-protection workflow; it does not replace it.

The API workflows expose:

- rack and tray leak status;
- tray and BMS sensor details, including optional readouts and thresholds;
- BMS leak-handling status;
- ongoing handling operations, such as tray shutdown or rack isolation;
- previous handling results and details.

This phase makes leak state and handling workflow available through the NICo API. BMS remains responsible for physical detection and remediation, while NICo provides the infrastructure-management health and lifecycle surface.

## Related documentation and implementation

- [Monitoring and Health](monitoring-health.md)
- `crates/dsx-exchange-consumer/README.md`
- `crates/dsx-exchange-consumer/src/health_updater.rs`
- `helm/README.md`
- [Issue #5018](https://github.com/NVIDIA/infra-controller/issues/5018)
