# Changelog

## [Unreleased](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.13-rc2-0...trunk)

### Added
### Changed
### Fixed
- Fixes redirect after Power Actions or BMC Reset have been issued on the carbide admin web UI.


### Removed

## [v2024.09.13-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.30-rc3-0...v2024.09.13-rc2-0)

### Added

- The preingestion state of an ExploredEndpoint is shown in the overview table on `/admin/explored-endpoint`.
- When objects are staying in a state longer than defined by the SLA.
  - The `state_reason` field in the objects API will be updated to indicate an `ERROR`. This error will also be rendered in the `State machine is blocked` field in the carbide web UI.
  - The metrics which indicate state handler errors (e.g. `forge_machines_with_state_handling_errors_per_state`) will indicate a `time_in_state_above_sla` error..
- Site Explorer now shows the `ComputerSystem`s `PowerState`.
- Site Explorer now gets the attached DPU's "base mac address" from Redfish instead of calculating it from `FirmwareInventory`.
- The FMDS endpoint will now include the intended BGP remote ASN at `meta-data/asn`.
- If a machine is in a state for longer than that state's SLA, the State Handler Outcome will report that it is out of SLA directly.
- Site Explorer will now emit time-series metrics for expected machines and missing machines (fixes: (FORGE-3353)[https://jirasw.nvidia.com/browse/FORGE-3353])
    - `forge_endpoint_exploration_expected_machines_missing_overall_count` - reports the number of machines in expected-machines that haven't been seen.
    - `forge_endpoint_exploration_failures_overall_count` - reports the number of explorations that have failed.
    - `forge_endpoint_exploration_preingestions_incomplete_overall_count` - the number of outstanding pre-ingestions.
    - `forge_endpoint_exploration_expected_serial_number_mismatches_overall_count` - the number of machine that don't match the expected serial number.
    - `forge_endpoint_exploration_machines_explored_overall_count` - The number of overall explored machines.
    - `forge_endpoint_exploration_identified_managed_hosts_overall_count` - The number of explored endpoints that were matched to the same `ManagedHost`
- The Admin UI now has buttons on Site Explorer to control the Host or DPU power.
- Added an API call to manually reset a BMC via Redfish or IPMI.
- Hardware health montioring is included and a config change in `carbide-api-site-config.toml` is required to set its behavior.
    - Options include:
        - `Disabled` (Default): Ignore all metrics sent by the hardware health service.
        - `MonitorOnly`: The aggregate health report will include reports from this service, but classifications are dropped.
        - `Enabled`: The aggregate health report will include reports, as well as their classifications to affect state processing.
    - Example:
        ```
        [host_health]
        hardware_health_reports = "MonitorOnly"
        ```
- Machine Validation will now update a machine's aggregate health.
    - If a validation test fails, a health alert with probe ID `FailedValidationTest` and a target that contains the validation tests `name` will be raised. The alert will be shown as part of the aggregate machine health.
    - Test results can now be viewed with `forge-admin-cli machine-validation`

### Changed

- `forge-admin-cli expected-machines` will now output in actual JSON instead of debug printing the internal structure.

### Fixed

- Fix link in carbide-web from ManagedHost overview page to DPU ExploredEndpoint page.
- The OpenTelemetry Collector on the DPU will now be restarted during a DPU upgrade (fixes: [4846975](https://nvbugspro.nvidia.com/bug/4846975)) to pick up the latest configuration.
- When machines have instances assigned to them and DPU reprovisioning fails, they will be put into an `Assigned/Failed` state vs `Failed` state (fixes: [4819135](https://nvbugspro.nvidia.com/bug/4819135)).
- In certain situtations where BMCs are non-responsive, carbide will automatically attempt to recover the BMC.
- Emit correct metrics if the hardware health service is enabled.

### Removed

## [v2024.08.30-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.30-rc2-0...v2024.08.30-rc3-0)

No user facing changes.

## [v2024.08.30-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.30-rc1-0...v2024.08.30-rc2-0)

### Added

- Added new view for showing the aggregate and DPU health report on the Admin UI for a managed host
- Allow to add Host health overrides via Admin UI
- Allow to update Infiniband default partition settings via three variables in the `carbide-api-site-config.toml`. Examples (and defaults) are:
  - mtu = 4
  - rate_limit = 200
  - service_level = 0
- Added GPU voltage, temperature, power metrics under `hw.gpu.[voltage|temperature|power|energy]`
- Added the ability to pre-define an associated DPU serial number to workaround hardware that does not provide Serial Numbers on Network Adapters in their Redfish API (see `forge-admin-cli expected machine --help` for details`
- Interim support for GH200 BMC - note this is not expected to be used in production hosts and will be replaced by G*B*200 support.
- Added username to adding credentials for a BMC since not all BMCs can use `root` as the main username, see `forge-admin-cli credentials add-bmc --help` for more details.

### Changed

- All admin-web UI pages and forge-admin-cli now show the aggregate Host Health report and the DPU health report, instead of the previous DPU-only health format (`NetworkHealth`).
- Health probe alert metrics for aggregate Host and DPU health now carry `probe_id` and `probe_target` attributes
- forge-dpu-agent directly uses `health_report` crate while assessing the health status of the DPU
- forge-dpu-agent emitted metrics now utilize the `target` for alerts like `FileExists` and `ServiceRunning` instead of encoding the target in the alert name.

### Fixed

- Fixed username handling of DGX H100 (Viking), these hosts cannot have the admin username be called 'root'
- DPU health metrics and component version metrics are correctly emitted for multi-dpu systems
- Fixed how DPUs-in-NIC-mode are being detected

### Removed

- Removed the `include_associated_machine_id` paramter to FindMachines as it's always included now.

## [v2024.08.16-rc2-2](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.16-rc2-1...v2024.08.16-rc2-2)

### Fixed

- Fix an issue with default block storage migration was not populating default data properly.

## [v2024.08.16-rc2-1](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.16-rc2-0...v2024.08.16-rc2-1)

### Fixed

- Fixed UEFI password handling on hosts

## [v2024.08.16-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.02-rc1-3...v2024.08.16-rc2-0)

### Added

- HBN logs are not collected from DPUs
- Added metrics for running versions for Carbide-PXE
- Numerous updates to the admin web ui (carbide-api/admin) for sorting and usability
- Expose new health reporting checks to the Admin UI
- Support for automatic host ingestion to work on DGX H100 (Vikings)
- Metrics added for when a DPU booted and when the DPU agent started
- Enabled Full mesh DPU latency monitoring in a site
- When upgrading DPUs to BFB 4.7.0, reset the Host BMC on Lenovo machines
- Re-enable updating the UEFI Password of DPUs and Hosts
- Added RedFish exploration metadata to JSON output for managed host

### Fixes

- Handle an edge case where SecureBoot may be enabled when we expecte it to be disabled
- Handle a DPU reboot if the DPU is stuck in WaitingForNetworkConfig
- Don't try to recover a machine if it could be updating firmware
- Fix a display issue when displaying the number of Free IPS in a Network Segment in the Admin CLI


## [v2024.08.02-rc1-3](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.02-rc1-2...v2024.08.02-rc1-3)

### Fixed

- An issue that causes opentelemetry agent to use excessive memory on the DPUs

## [v2024.08.02-rc1-2](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.02-rc1-1...v2024.08.02-rc1-2)

### Fixed

- Fixed an issue where the automatic DPU reprovisioning process would use the wrong credentials

## [v2024.08.02-rc1-1](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.02-rc1-0...v2024.08.02-rc1-1)

### Added

- Added a new display to the Admin UI that lists hosts that are missing (but expected) and unlinked hosts
- Added a workaround for DPU UEFI / BMC race condition after power-cycling a host after installing HBN

### Fixed

- Fixed an issue disabling SecureBoot on a DPU (SecureBoot must be disabled twice and then power cycled)
- Fixed the DPU-DPU latency monitor to use the DPU loopback instead of the Out-of-Band

## See git logs for older versions than the v2024.08.02 fixes
