# Changelog

## [Unreleased](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.30-rc1-0...trunk)

### Added

- Added new view for showing the aggregate and DPU health report on the Admin UI for a managed host
- Allow to add Host health overrides via Admin UI
- Allow to update Infiniband default partition settings via three variables in the `carbide-api-site-config.toml`. Examples (and defaults) are:
  - mtu = 4
  - rate_limit = 200
  - service_level = 0

### Changed

- All admin-web UI pages and forge-admin-cli now show the aggregate Host Health report and the DPU health report, instead of the previous DPU-only health format (`NetworkHealth`).
- Health probe alert metrics for aggregate Host and DPU health now carry `probe_id` and `probe_target` attributes

### Fixed

- Fixed username handling of DGX H100 (Viking), these hosts cannot have the admin username be called 'root'
- DPU health metrics and component version metrics are correctly emitted for multi-dpu systems

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
