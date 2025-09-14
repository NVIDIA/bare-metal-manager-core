
# Changelog

## [Unreleased (v2025.09.26-rc1-0)](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.09.12-rc2-0...trunk)

### Added

### Changed

### Fixed

### Removed

### Internal Changes

## [Unreleased (v2025.09.10-rc2-0)](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.08.29-rc2-0...v2025.09.10-rc2-0)

### Added

- [MR-4561](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4561): Added  support for an unused feature still in development. The `mqttea` client isn't in use anywhere yet, and the MR to actually integrate with it is still in development. And even though it's not in use yet, it's still backwards compatible just in case.
- [FORGE-6424](https://jirasw.nvidia.com/browse/FORGE-6424), [MR-4546](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4546): Added the ability to monitor the amount of changes applied via UFM APIs via a new `forge_ib_monitor_machine_ufm_changes_applied_total` metric.
- [MR-4415](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4415): Added the ability to supress external alerts by matching the new `forge_alerts_suppressed_count` metric with hosts with the SuppressAlerts classification.
- [MR-4533](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4533): Added the ability to enable infinite boot and check its current status for Dells, Lenovos, Vikings, and **GB200s** using `forge-admin-cli`.
- [MR-4496](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4496): Added next state information to the `time_in_state` metric to better explain and distinguish the metric data.
- [FORGE-6584](https://jirasw.nvidia.com/browse/FORGE-6584), [MR-4513](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4513): Added the ability to automatically trigger an AC power cycle on Lenovo machines when stuck.
- [FORGE-6679](https://jirasw.nvidia.com/browse/FORGE-6679), [MR-4490](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4490): Added the ability for carbide to continously monitor the desired IB configuration at Carbide, the actually deployed IB configuration (GUID to pkey associations at UFM), and applies any fixes that are required to set the desired configuration.

### Fixed

- [5504750](https://nvbugspro.nvidia.com/bug/5504750), [MR-4559](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4559): Disables reboot in fw-check routine.
- [5472630](https://nvbugspro.nvidia.com/bug/5472630), [MR-4549](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4549), [MR-4544](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4544): Ensured that site explorer, expected machines, and Nautobot align on the serial numbers assigned to GB200s, preventing `SerialNumberMismatch` health alerts. GB200 serial numbers can also be sourced from `/redfish/v1/Chassis/Chassis0/Assembly` now, and this MR now allows site explorer to recognize this. Previously, this chassis was ignored because it had no network adaptors.
- [FORGE-1234](https://jirasw.nvidia.com/browse/FORGE-1234), [MR-4538](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4538): Bump libredfish to 0.29.71 to pull in a fix to setting the boot order on Lenovo SR 675 V3s.
- [MR-4550](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4550): Fixed an issue when running FNN with a legacy admin network where the unused DPU in an instance was configured to use FNN on the admin network.
- [5499287](https://nvbugspro.nvidia.com/bug/5499287), [MR-4542](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4542): Handles the race condition where tenant requests a instance and at the same time carbide also triggers reprovision.
- [MR-4536](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4536): Fixed an issue with the time taken to render /admin/managed-host by reducing it's execution time from 22 seconds down to 0.6 seconds (on a database with 800 managed hosts).
- [5486954](https://nvbugspro.nvidia.com/bug/5486954), [MR-4528](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4528): Fixed an issue where the new DPU reprovisioning flow doesn't run because of inaccurate BMC information in the database.
- [MR-4531](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4531): GB200 firmware fixes.

### Internal Changes

- [MR-4535](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4535): Fix auto-deploy script so it pushes direct to forged/main.
- [MR-4553](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4553): chore: Zero initialize forge_ib_monitor_ufm_changes_applied_total metric.
- [FORGE-1234](https://jirasw.nvidia.com/browse/FORGE-1234), [MR-4537](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4537): refactor: database error handling unification in the Carbide API: errors with transactions.
- [FORGE-1234](https://jirasw.nvidia.com/browse/FORGE-1234), [MR-4540](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4540): refactor: database error handling unification in the Carbide API: errors with transactions part 2.
- [FORGE-1234](https://jirasw.nvidia.com/browse/FORGE-1234), [MR-4541](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4541): refactor: database error handling unification in the Carbide API: tracking file / line using track_caller Rust feature.
- [MR-4548](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4548): refactor: remove unnecessary explicit conversions to CarbideError.

- [FORGE-6905](https://jirasw.nvidia.com/browse/FORGE-6905), [MR-4539](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4539): chore: Add CODEOWNERS file.
- [MR-4555](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4555): chore: Unify to a single MachineId type.
- [FORGE-1234](https://jirasw.nvidia.com/browse/FORGE-1234), [MR-4524](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4524): Added Merge Request template.
- [MR-4532](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4532): database error handling unification in the Carbide API: errors with query.
- [MR-4529](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4529): chore: tests: Added: TestManagedHost::machine_validation_completed.
- [MR-4530](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4530): Updated libredfish to trunk and fix bmc-mock to support chassis collection.
- [5481973](https://nvbugspro.nvidia.com/bug/5481973), [MR-4519](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4519): Add check for password reset during machine lifecycle test.
- [MR-4527](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4527): Empty commit to advance tag.

## [v2025.08.29-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.08.15-rc2-0...v2025.08.29-rc2-0)

### Added

- [MR-4343](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4343): Added support for SPX in API, DB and State Machines.
- [5469577](https://nvbugspro.nvidia.com/bug/5469577), [MR-4485](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4485): Added the ability to validate expected machines serial number.
- [MR-4468](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4468): Added the ability to manage route servers using `forge-admin-cli route-server add|get|remove|replace`.
- [MR-4489](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4489): Added the ability to report a leak using new health report for affected machines.
- [MR-4478](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4478): Added the ability to manage "GPU" firmware.
- [FORGE-6728](https://jirasw.nvidia.com/browse/FORGE-6728), [MR-4451](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4451): Added the ability to force assignment of a SKU to a machine using `forge-admin-cli`.
- [MR-4265](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4265): Added the ability to use custom cloud-init if it is configured for an instance.
- [MR-4449](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4449): Added the ability to determine wheather an IB config is fully applied to a host without having to load the IB partition details.
- [MR-4395](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4395): Added ability to do host upgrades via script instead of the normal firmware update process.

### Changed

- [FORGE-6725](https://jirasw.nvidia.com/browse/FORGE-6725), [MR-4450](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4450): Changed default setting for generation of SKUs to `false`.
- [MR-4522](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4522): Split alerts out on separate lines in managed-host show cli command.
- [MR-4525](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4525) Handle GB200 not supporting lockdown for upgrades.

### Fixed

- [MR-4501](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4501): Fixed an issue where some IB ports showed up as mz5_1 instead of the correct persistent name.
- [MR-4514](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4514): Fixed an issue where `-x` was missing in `pre_components_update` function.
- [5478817](https://nvbugspro.nvidia.com/bug/5478817), [MR-4508](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4508): Fixed an issue where disks would fill up when the `bfvcheck` command would be killed due to a too small timeout.
- [MR-4509](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4509): Fixed an issue when a failed sensor would create a health override for the host as if the sensor was working.
- [MR-4486](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4486): Fixed an issue where sensor Degraded State was undiscovered in redfish calls.
- [MR-4484](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4484): Fixed an issue in ssh-console where any characters received after the last newline were not displayed withouth the user having to press enter.
- [MR-4483](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4483): Fixed an issue in exponential backoff time of ssh-console that caused a crash.
- [MR-4481](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4481): Fixed an issue where messages would not be written out when connecting / disconnecting from BMC's.
- [MR-4472](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4472): Fixed an issue where a stack overflow can occur in site-explorer.
- [FORGE-6680](https://jirasw.nvidia.com/browse/FORGE-6680), [MR-4482](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4482): Fixed an issue in the state machine where we did not wait for the desired and actual instance configuration for IB became synced.
- [MR-4477](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4477): Fixed an issue with reading GB200 thermal metrics.
- [FORGE-6803](https://jirasw.nvidia.com/browse/FORGE-6803), [MR-4476](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4476): Fixed an issue where a dependency removed the `InSecureClientIP` structure.
- [MR-4467](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4467): Fixed an issue in `forge-admin-cli` where an error is printed also in the successful case when disassociating instance type with a machine.
- [MR-4460](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4460): Fixed an issue in machine state handler where secure boot was not correctly enabled using the new redfish flow.
- [MR-4461](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4461): Fixed an issue in ssh-console where we didn't allocate a PTY and requested a shell for DPUs.
- [MR-4453](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4453): Fixed an issue in carbide-web where associated pkeys were not consistently formatted.
- [MR-4446](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4446): Fixed an issue in ssh-console where exponential backoff for connecting to the BMC would cause long wait times on machines where the BMC was offline.
- [FORGE-4766](https://jirasw.nvidia.com/browse/FORGE-4766), [MR-4443](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4443): Fixed an issue where scout was not logging API communication errors after a `ForgeAgentControlRequest`.
- [FORGE-6795](https://jirasw.nvidia.com/browse/FORGE-6795), [MR-4458](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4458): Fixed an issue where the `forge_machines_time_in_state_seconds` metrics were not correctly calculated.

### Removed

- [MR-4515](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4515): Removed internal cronjob to clean up the `/tmp` directory since the bug causing it to fill up on DPUs has been addressed.
- [FORGE-6856](https://jirasw.nvidia.com/browse/FORGE-6856), [MR-4495](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4495): Removed VRAM from SKU comparison since it may change depending on GPU mode.

### Internal Changes

- [MR-4517](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4517): libredfish 0.29.65.
- [MR-4511](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4511): formalize mlxconfig variable management with mlxconfig variable registry.
- [MR-4510](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4510): chore: allow_failure for unstable dev-env-test-with-carbide.
- [MR-4507](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4507): chore: tests: create_managed_host_with_config returns ManagedHost.
- [FORGE-6863](https://jirasw.nvidia.com/browse/FORGE-6863), [MR-4504](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4504): Redfish actions access from tests.
- [MR-4502](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4502): chore: tests: managed host in rest of host_bmc_firmware_test.
- [MR-4499](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4499): chore: ssh console: get rid of allow warn.
- [MR-4425](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4425): allow mac builds with no default features.
- [MR-4494](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4494): chore: tests: intro: TestInstance and new way of building instances.
- [MR-4493](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4493): feat: simplify powerdns container.
- [MR-4492](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4492): chore: tests: remove: unused_dpu_machine_ids are not really used.
- [MR-4491](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4491): chore: remove: ip_finder.rs empty unused file.
- [MR-4487](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4487): chore: tests: ManagedHost helper. for multidpu and host_with_ek.
- [MR-4488](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4488): chore: Cleanup instance api_fixtures.
- [MR-4479](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4479): chore: tests: ManagedHost helper introduced.
- [MR-4480](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4480): chore: Box various state controller runs in unit-tests.
- [MR-4471](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4471): fix: switch from generic type param -> impl trait arg.
- [FORGE-6794](https://jirasw.nvidia.com/browse/FORGE-6794), [MR-4469](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4469): chore: FORGE-6794: tests: instances: complete: rpc instance helper.
- [FORGE-6807](https://jirasw.nvidia.com/browse/FORGE-6807), [MR-4470](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4470): chore: FORGE-6807: add missing dependency for pages.
- [FORGE-6130](https://jirasw.nvidia.com/browse/FORGE-6130), [MR-4452](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4452): chore: FORGE-6130: book: machine FSM: new diagrams.
- [FORGE-6801](https://jirasw.nvidia.com/browse/FORGE-6801), [MR-4464](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4464): refactor: FORGE-6801: more ways to convert MachineId to rpc.
- [MR-4465](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4465): chore: tests: remove confusing ManagedHostSim.
- [FORGE-6707](https://jirasw.nvidia.com/browse/FORGE-6707), [MR-4413](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4413): refactor: FORGE-6707: ExpectedMachineData introduced.
- [FORGE-6794](https://jirasw.nvidia.com/browse/FORGE-6794), [MR-4457](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4457): chore: FORGE-6794: tests: instances: added rpc instance helper.
- [MR-4454](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4454): fix: typo: BIOS => BOSS.
- [MR-4521](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4521): Unit tests: separate modules for test object helpers.

## [v2025.08.15-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.08.01-rc2-0...v2025.08.15-rc2-0)

### Added

- [FORGE-6021](https://jirasw.nvidia.com/browse/FORGE-6021), [MR-4370](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4359): Ability to link an expected machine to a SKU.
  When site-explorer creates machines, it will automatically assign a SKU specified in the expected machine to the new machine.
  SKUs have a new field "device_type" that available for the user to edit.  It is considered metadata and does not affect how BOM validation works.
  forge-admin-cli gets the following changes:
  - `sku update-metadata <--description <DESCRIPTION>|--device-type <DEVICE_TYPE>> <SKU_ID>` allows updates of the sku description and device type.
  - `expected-machines update` gains a --sku-id flag for updating the sku in the expected machine.
  - `expected-machines add` gains a --sku-id flag for updating the sku in the expected machine.
  - `expected-machines show` shows the sku id.
  - `expected-machines replace-all` takes an optional sku_id in the input json.
  - machine state machine has a new state `BomValidation/SkuMissing` to handle the situation when the sku specified in the expected machine does not exist.
  - new metrics are emitted for the number of machines associated with a sku and/or device_type.
- [MR-4436](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4436): Added the ability to rotate logs in ssh-console.
- [FORGE-6762](https://jirasw.nvidia.com/browse/FORGE-6762), [MR-4431](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4431): Added the ability to replace components of a SKU.
- [FORGE-6725](https://jirasw.nvidia.com/browse/FORGE-6725), [MR-4427](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4427): Added the ability to auto-generate SKUs for machines with SKUs specified in expected machines.
- [MR-4433](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4433): Added the ability to enforce stricter ARP/neighbor learning on tenant networks. Note that this could be a breaking change if a tenant workload relies on being able to inject neighbor entries (via GARP or otherwise) that are outside of a subnet prefix.
- [FORGE-3181](https://jirasw.nvidia.com/browse/FORGE-3181), [MR-4428](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4428): Added the ability to remove `TenantReportedIssue` health override when an instance is release from the repair-tenant after the instance was fixed.
- [FORGE-5704](https://jirasw.nvidia.com/browse/FORGE-5704), [MR-4407](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4407): Added the ability to receive alerts if the default IB partition is not in limited membership mode.
- [FORGE-6611](https://jirasw.nvidia.com/browse/FORGE-6611), [MR-4308](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4308): Added the ability to for DPA to interface with carbide using MQTT.
- [FORGE-3181](https://jirasw.nvidia.com/browse/FORGE-3181), [MR-4345](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4345): Added the ability for forge to integrate with node lifecycle management in Lazarus.
- [MR-4400](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4400): Added the ability to enable TPM on SMCs using Redfish.
- [FORGE-6608](https://jirasw.nvidia.com/browse/FORGE-6608), [MR-4397](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4397): Added the ability to return sitename to tenants via FMDS endpoint.
- [MR-4386](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4386): Added the ability to use `output_file` for `machine show`, `instance show`, and `sku show` commands for writing the output to a file.
- [MR-4342](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4342): Added the ability to do script-based firmware upgrades for handling insufficient manufacturing procedures.
- [MR-4369](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4369): Added the ability to remove instance-type association from an instance in terminating state using forge-admin-cli.

### Changed

- [MR-4426](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4426): Changed version of Rust to 1.88 and resolved new issues repored by clippy.
- [MR-4430](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4430): Changed ssh-console to use custom errors instead of eyre.
- [MR-4417](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4417): Changed known firmware versions for Bluefield 2.
- [MR-4394](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4394): Changed the version of the recommended DPU firmware for checking the UEFI certificate loading workaround to 4.9.3.
- [MR-4390](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4390): Changed Bluefield 2 version for 2.9.3.
- [MR-4383](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4383): Changed the scout images to be consistent across the two platforms and updated some drivers.
- [MR-4281](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4281): Changed DOCA version to 2.9.3 LTS.

### Fixed

- [MR-4421](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4421): Fixed an issue where setting the boot order on Supermicro systems failed when there are pending BIOS settings.
- [FORGE-5333](https://jirasw.nvidia.com/browse/FORGE-5333),[MR-4393](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4393): Fixed an issue where the version was not updated for a machine when its instance type association was updated.
- [MR-4420](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4420): Fixed an issue in ssh-console where the whole buffer of ipmitool errors was printed instead of readable characters.
- [MR-4416](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4416): Fixed an issue in ssh-console where it is not getting data from some IPMI consoles.
- [MR-4409](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4409): Fixed an issue where the DPU would get the sitename during every `GetManagedHostNetworkConfig` RPC call and not just once during initialization.
- [MR-4402](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4402): Fixed an issue in forge-admin-cli where disassociation of instance-type was not handled for non-instance machines.
- [MR-4399](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4399): Fixed an issue where site explorer would clone expected machines on each cycle.
- [MR-4392](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4392): Fixed an issue with drivers in the scout image for successfully running `dcgmi diag -r[1-3]`.
- [MR-4391](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4391): Fixed an issue where the BMC firmware versions were not correctly compared to support bfb installation.
- [FORGE-6224](https://jirasw.nvidia.com/browse/FORGE-6224), [MR-4384](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4384): Fixed an issue where the `version` command in forge-admin-cli would require a client certificate.
- [MR-4306](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4306): Fixed an issue where we didn't do an AC power cycle for HGX firmware updates on GB200.
- [FORGE-6524](https://jirasw.nvidia.com/browse/FORGE-6524), [MR-4293](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4293): Fixed an issue where the timeout for the background upload for host firmware for ingested machines was too low (now at 1 hour).

### Internal Changes

- [MR-4432](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4432): Fixed a few clippy warnings after various trivial crate updates.
- [MR-4429](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4429): Refactored location of BFB config values into a central location.
- [MR-4434](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4434): Fixed an issue with println! format strings to use direct variable interpolation.
- [FORGE-6735](https://jirasw.nvidia.com/browse/FORGE-6735), [MR-4424](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4424): Refactored site explorer tests.
- [FORGE-6690](https://jirasw.nvidia.com/browse/FORGE-6690), [MR-4418](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4418): Restructure sub-state selection code based on the BFB installation capability.
- [FORGE-6698](https://jirasw.nvidia.com/browse/FORGE-6698), [MR-4414](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4414): Remove clippy lint disablings in carbide.
- [MR-4403](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4403): Added PCIe-device properties to machine-o-tron.
- [FORGE-6699](https://jirasw.nvidia.com/browse/FORGE-6699), [MR-4401](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4401): Refactored remove clones related to site explorer.
- [MR-4411](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4411): Changed pipeline to allow merge conflict in pre-merge dev-env test.
- [FORGE-6705](https://jirasw.nvidia.com/browse/FORGE-6705), [MR-4410](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4410): Use builder pattern to create test instances.
- [MR-4406](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4406): Fixed documentation issues for MQTTEA README.md.
- [MR-4388](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4388): Make sure pre-commit-verify-workspace checks all code.
- [MR-4385](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4385): Refactoring and renaming in ssh-console.
- [FORGE-6700](https://jirasw.nvidia.com/browse/FORGE-6700) [MR-4405](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4405): Added clone clippy warnings.
- [MR-4396](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4396): Changed machine-lifecycle-test pipeline to rebuild MLT image on every merge.
- [MR-4387](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4387): Added documentation for alerts and Panoptes.
- [MR-4138](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4138): Added documentation for using Grafana Tempo in local development environment.
- [MR-4382](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4382): MLT: Remove Rust struct workaround.
- [MR-4349](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4349): Added a script for machine-a-tron mocks to generate multiple nginx instances.

## [v2025.08.01-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.07.18-rc2...v2025.08.01-rc2-0)

### Added

- [FORGE-6650](https://jirasw.nvidia.com/browse/FORGE-6650), [MR-4351](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4351): Added the ability to assign missing SKUs to machine from expected machines table.
- [FORGE-6437](https://jirasw.nvidia.com/browse/FORGE-6437), [MR-4358](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4358): Added the ability to reuse existing reports for measured boot if they are the same by only updating their timestamp.
- [FORGE-6424](https://jirasw.nvidia.com/browse/FORGE-6424), [MR-4361](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4361): Added the ability to record all partition keys associated with each GUID from the UFM API.
- [MR-4356](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4356): Added the ability to query the amount of ingested hosts per SKU as a metric via `forge_hosts_by_sku_count{sku="..."}`.
- [FORGE-6649](https://jirasw.nvidia.com/browse/FORGE-6649), [MR-4350](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4350): Added the ability to add SKU IDs to expected machines via the new forge-admin-cli parameter `--sku-id`. For example `forge-admin-cli em add [...] --sku-id <SKU_ID>`.
- [MR-4348](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4348): Added the ability for importing additional routes in FNN to be able to add new and rotate out old configurations.
- [MR-4346](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4346): Added the ability to explicity configure the common FNN internal route-target to support newer data centers where the ASN+VNI will exceed the 6-byte limit.
- [MR-4324](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4324): Added metrics support to ssh-console.
- [FORGE-6230](https://jirasw.nvidia.com/browse/FORGE-6230), [FORGE-6505](https://jirasw.nvidia.com/browse/FORGE-6505), [MR-4259](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4259): Added the ability to change a machine's power state to a desired power state in the state machine and to view details using `admin-cli mh power-options show`. Power manager is *disabled* by default and can be enabled in the `[power_manager_options]` section of the carbide configuration by setting `enabled = true`.
- [FORGE-6556](https://jirasw.nvidia.com/browse/FORGE-6556), [MR-4333](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4333): Added the ability to issue an AC Power Cycle using carbide-web or `forge-admin-cli bmc admin-power-control --machine <id> --action ac-powercycle`.
- [MR-4330](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4330): Added FNN updates for Virtual Functions support.
- [MR-4321](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4321): Added the ability to login to the scout image and DPU with sudo rights depending on membership in administrative groups.
- [MR-4331](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4331): Fixed an issue with inconsistent versions and missing packages in the scout image due to discrepencies in the Ubuntu and Nvidia repos.
- [MR-4337](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4337): Added the ability to differentiate if a port was not found in UFM or if it is set to `0xffff` because the port is down.
- [MR-4332](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4332): Added the ability to query IB port state count metrics via `forge_ib_monitor_machines_by_port_state_count{active_ports="...",total_ports="..."}`.
- [MR-4328](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4328): Added the ability to create and delete BMC users through the carbide-api.
- [MR-4316](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4316): Added the ability to use the `forge-admin-cli instance allocate` to configure VF interfaces.
- [MR-4318](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4318): Added the ability to sort the output of `forge-admin-cli machine show`, `... managed-host show` and `... instance show` by use of the `--sort-by` argument.
- [MR-4374](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4374): Add a new metric forge_ib_monitor_machines_by_ports_with_partitions_count which describes the amount of Machines where a certain amount ports is associated with at least one partition.
- [MR-4377](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4374), [MR-4379](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4374): Add new metrics forge_ib_monitor_machines_with_missing_pkeys_count and forge_ib_monitor_machines_with_unexpected_pkeys_count which allow to detect configuration drift between Carbide and UFM. Also adds log lines that precisely show which ports/guids are not assigned to the expected pkeys.

### Changed

- [MR-4368](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4368): Changed QoS configuration data to be an optional parameter `Option<IBQosConf>`.
- [MR-4311](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4311): Changed setting the boot order in carbide-web to feature the option in the BMC section, and to accept any boot interface MAC address in the explored endpoint page.
- [MR-4326](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4326): Changed the querying of UFM and the update of `ib_status_observation` into the IBFabricMonitoring task.
- [MR-4320](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4320): Changed the autorestart behavior of dhcp-server to restart independently of the error.
- [MR-4325](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4325): Changed UfmClient API to allow specifying if `guid_data` or `qos_conf` data should be included and moved the functionality of `list_partition_ports` to `get_partition`.
- [MR-4322](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4322): Changed ssh-console to always connect to all backends and retry forever even if logging is disabled.
- [MR-4307](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4307): Changed IbFabricMonitor to only run a single instance.
- [MR-4375](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4375): Changed IB Partition Status API to return the pkey in hexadecimal instead of decimal format.

### Fixed

- [MR-4365](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4365): Fixed an issue where on the fly compilation of regular expresions was contributing to about 12% of CPU load of the site explorer.
- [MR-4363](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4363): Fixed an issue where machines were continuously rebooted due to last_reboot_requested field not being updated correctly.
- [MR-4362](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4362): Fixed an issue where fetching partition information in IbFabricMonitor would fail due to a UFM bug or the false assumption that QoS data is always returned.
- [MR-4341](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4341): Fixed an issue in UFM browser failing when browsing non-existing objects.
- [MR-4339](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4339): Fixed an issue with network fluctuation during admin to tenant network switch in dhcp-server.
- [MR-4314](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4314): Fixed an issue where forge-scout is unable to enumerate the IB ports by ensuring mlx5_ib loads after udev is up and running.
- [MR-4335](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4335): Fixed an issue in forge-admin-cli with ambiguous `m` argument for create BMC user and delete BMC user commands.
- [MR-4338](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4338): Fixed an issue where a response from UFM with `{}` would not be interpreted as "not found".
- [FORGE-6613](https://jirasw.nvidia.com/browse/FORGE-6613), [MR-4315](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4315): Fixed an issue with hung `nvidia-smi` by adding a timeout to the command execution.
- [FORGE-6604](https://jirasw.nvidia.com/browse/FORGE-6604), [MR-4312](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4312): Fixed an issue where only the first interface in an instance's network config is having an `internal_uuid` set.
- [MR-4304](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4304): Fixed an issue where BIOS jobs interacting with BOSS controllers where not handled in state machine.
- [MR-4302](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4302): Fixed an issue with a service dependency of otelcol-contrib on the DPU and added a startup retry for up to 10 minutes.
- [MR-4300](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4300): Fixed serveral issues with ssh-console, resulting from testing it in dev3 environment.
- [FORGE-5698](https://jirasw.nvidia.com/browse/FORGE-5698), [MR-4292](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4292): Fixed an issue where `forge-admin-cli machine show` reports old firmware versions instead of the current versions.

### Removed

- [MR-4136](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4136): Removed label configurations for auth logs in OTEL on the DPU.

### Internal Changes

- [MR-4360](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4360): Fixed an issue in machine-lifecycle-test to wait for a machine to be ready in the cloud.
- [MR-4353](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4353): Refactored code to use turbofish syntax for some `collect()` calls.
- [MR-4355](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4355): Added the information on how to get support to the documentation.
- [MR-4352](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4352): Changed the hardware section in the documentation to include hardware summary information and improved the document structure.
- [MR-4347](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4347): Added the Lenovo SR 675 hardware information to the documentation.
- [MR-4340](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4340): Added the ability to prevent rebuilding forge-version using the environment variable `FORGE_VERSION_AVOID_REBUILD=1`.
- [MR-4334](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4334): Fixed an issue where DB tests will fail during creation of a database with an existing name.
- [MR-4327](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4327): Improved the performance of unit tests by using template DB.
- [MR-4329](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4329): Fixed an issue where timestamps were disabled in CI because of corrupted logs.
- [MR-4305](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4305): Refactored code to reduce the number of `clone()` operations.
- [MR-4319](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4319), [MR-4317](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4317): Changed the machine lifecycle test to disable scheduled pipelines on failure.
- [MR-4313](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4313): Added the Lenovo SR 670 V2 hardware information to the documentation.
- [MR-4310](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4310): Fixed issues from clippy warnings in ssh-console fuzz tests.
- [MR-4301](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4301): Refactored ssh-console configuration for easier (de)serialization.

## [v2025.07.18-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.07.04-rc2-0...v2025.07.18-rc2)

### Added

- [MR-4289](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4289): Added RBAC for ssh-console-rs.
- [MR-4287](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4287): Added the ssh-console binary to the carbide release-container-x86_64.
- [MR-4267](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4267): Added ssh-console logging support. Logging can be enabled by adding the `-g` flag to the `SSH_CONSOLE_ARGS` variable in the `ssh-console-site-config.toml` file.
- [MR-4213](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4213): Added the latest firmware documentation to the Forge Book.
- [FORGE-6464](https://jirasw.nvidia.com/browse/FORGE-6464), [FORGE-6465](https://jirasw.nvidia.com/browse/FORGE-6465), [MR-4256](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4256): Added the ability to setup the DPU as the first boot entry using carbide-web and to view the boot interface MAC in the Forge Setup section for Dell machines.
- [FORGE-6070](https://jirasw.nvidia.com/browse/FORGE-6070), [MR-4133](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4133): Added the ability to use a virtual function ID to more reliably delete virtual functions.
- [MR-4248](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4248): Added IPMI support to ssh-console and sharing support so that multiple connections to the same backend use a single connection.
- [FORGE-6469](https://jirasw.nvidia.com/browse/FORGE-6469), [MR-4250](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4250): Added the ability to create an instance from an unhealthy machine.
- [FORGE-5908](https://jirasw.nvidia.com/browse/FORGE-5908), [MR-3933](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3933): Added the ability to use DPU machine ID for instance allocation to support multiple DPUs per instance.
- [MR-4273](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4273): Added the ability to view when the Infiniband status was last updated from UFM so that users can troubleshoot issues with UFM updates.
- [MR-4254](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4254): Added the ability to explicitly configure the boot order on Dell machines during the ingestion flow so that the HTTP boot option corresponding to the primary DPU is the first in the list.
- [MR-4234](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4234): Added the ability to only add SPAN tracer when an OTEL endpoint is configured.
- [MR-4252](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4252): Added the information for Haifa jumpbox & staging servers in the documentation.
- [FORGE-6422](https://jirasw.nvidia.com/browse/FORGE-6422), [MR-4237](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4237): Added support for updating and clearing machine instance types in forge-admin-cli using `forge-admin-cli instance-type associate --help` and `forge-admin-cli instance-type r --help`.
- [MR-4244](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4244): Added a link to the troubleshooting document of `noDpuLogsWarning` alerts in the documentation.

### Changed

- [MR-4261](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4261): Changed the location of BMC-related actions in carbide-web to a dedicated BMC section.
- [MR-4257](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4257): Changed the error and response reporting in the UFM client for better troubleshooting of HTTP status codes, response body and headers.

### Fixed

- [MR-4288](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4288): Fixed an issue with noisy error handling in ssh-console and made authentication rejections faster.
- [5392545](https://nvbugspro.nvidia.com/bug/5392545), [MR-4278](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4278): Fixed an issue where during BFB installation new state versions were created even though the task has not progressed (in terms of its percentage completed).
- [MR-4264](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4264): Fixed an issue where the forge-scout package install would fail in cases when it was not build under root.
- [MR-4279](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4279): Fixed an issue where ssh-console front-ends were not disconnected in cases where the backed disconnected.
- [MR-4280](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4280): Fixed an issue where removable drives where not ignored during hardware enumeration.
- [MR-4277](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4277): Fixed an issue with setting the network boot order on Lenovo machines.
- [MR-4276](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4276): Fixed an issue where the `observed_at` timestamp for IB status was confusing as it is actually the last changed timestamp. The property was renamed accordingly to `last_changed_at`.
- [MR-4269](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4269): Fixed an issue where the mlx5_ib module was not loaded automatically before scout starts, causing missing IB ports in the inventory.
- [MR-4272](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4272): Fixed an issue where writing configuration files exceeding the MAX_EXPECTED_SIZE would not be blocked immediately. We now fail early and, depending on the cause, allow the tenant to correct issues without having to terminate their instance.
- [MR-4271](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4271): Fixed an issue where the Infiniband status would only update in `Ready` and `Assigned` states which causes BOM validation failures to never recover as a new status would never be observed. With this fix, the status is also updated in the BOM validation states.
- [MR-4262](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4262): Fixed an issue where instances could not be successfully terminated because the NVUE config exceeded the MAX_EXPECTED_SIZE and therefore could not switch to the admin network. With this fix, we force a config write when switching to the admin network.
- [MR-4260](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4260): Fixed an issue where NVUE configuration updates would fail because the config is too large for a diff check.
- [MR-4255](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4255): Fixed an issue with pagination for the `FindInstanceTypesByIdsRequest` request by deduplicating instant type IDs.
- [FORGE-6197](https://jirasw.nvidia.com/browse/FORGE-6197), [FORGE-6198](https://jirasw.nvidia.com/browse/FORGE-6198), [MR-4253](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4253): Fixed an issue where machines that are in `Ready` state for longer durations would not automatically update to newer versions of scout.
- [5318791](https://nvbugspro.nvidia.com/bug/5318791), [MR-4239](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4239): Fixed an issue where the startup order of OpenTelemetry collector on the DPU would cause the hostname to be reported as `localhost` instead of the DPUs actual hostname, yielding in `noDpuLogsWarning` alerts.
- [MR-4251](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4251): Fixed an issue where the the wrong GRPC message name for `GetManagedHostNetworkConfig` was written to the logs.

### Removed

- [FORGE-6426](https://jirasw.nvidia.com/browse/FORGE-6426), [MR-4206](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4206): Removed the unnecessary `--id` flag in `forge-admin-cli nsg show` commmand.

### Internal Changes

- [MR-4283](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4283): Fixed random failures of test_find_machine_by_mac.
- [MR-4285](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4285): Fixed an issue with ssh-console tests when localhost is an ipv6 address.
- [MR-4284](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4284): Improved InfiniBand related unit-test coverage and test framework.
- [MR-4282](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4282): Added server status decode exception handler to machine lifecycle tests.
- [MR-4270](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4270): Delay cleanup confirmation in Machine-A-Tron.
- [MR-4268](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4268): Fixed an error message if a tar file was not found in bmc-mock.
- [MR-4247](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4247): Machine-a-tron config file path check.
- [MR-4258](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4258): Improved success rate of integration test.

## [v2025.07.04-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.06.20-rc1-0...v2025.07.04-rc2-0)

### Added

- [MR-4162](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4162): Added `pre_update_resets` option for host firmware that will go through a series of steps that will enhance updates.
- [MR-4236](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4236): Added power options to host snapshot.
- [FORGE-6312](https://jirasw.nvidia.com/browse/FORGE-6312), [MR-4224](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4224): Added kernel headers to ensure modules are built correctly.
- [FORGE-6230](https://jirasw.nvidia.com/browse/FORGE-6230), [MR-4228](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4228): Added support to handle power options for a host in `forge-admin-cli` to be able to set the desired power state, e.g. `forge-admin-cli mh power-options update <machine id> --desired-power-state off`.
- [FORGE-6230](https://jirasw.nvidia.com/browse/FORGE-6230), [MR-4192](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4192): Added support for storing power related parameters for machines.
- [MR-4167](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4167): Added `host_machine_id` label to DPU logs for easier search of DPU logs in multi-DPU systems. This should also address an issue related to `noDpuLogsWarning`.
- [MR-4210](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4210): Added the list of machine IDs that are associated with an instance type in carbide-web on its details page.
- [MR-4215](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4215): Added the ability to query for machine IDs by instance type in the carbide API.
- [MR-4209](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4209): Added the ability to navigate from the SKU details page to its associated machines in carbide-web via hyperlink.
- [MR-4197](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4197): Added the ability to navigate from carbide-web's display of source code file name and line number to the source code in gitlab.
- [MR-4196](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4196): Added the ability to view detailed state handler outcome including source code locations for network segments and IB partitions in carbide-web.
- [MR-4195](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4195): Added the ability to view the source code file and line number when the state handler returns with an `Ok` outcome to be able to understand why a machine might be stuck due to a certain condition.

### Changed

- [MR-4225](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4225): Changed the boot console output to include hints on how to re-run OS installation.
- [MR-4212](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4212), [MR-4193](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4193): Changed the host health page styling.

### Fixed

- [MR-4220](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4220): Fixed an issue where a tenant state of `Terminating` was reported during firmware updates.
- [MR-4243](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4243): Fixed an issue with exploration of a BMC that has an Ethernet interface for which we cannot parse the MAC address in cases where the interface is not up.
- [MR-4242](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4242): Fixed an issue where the machine link in carbide-web on the attestation page would not work as expected.
- [FORGE-6502](https://jirasw.nvidia.com/browse/FORGE-6502), [MR-4240](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4240): Fixed an issue where clearing exploration errors would reset the preingestion state to `Complete`.
- [MR-4238](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4238): Fixed an issues where DPUs would not be correctly shown in forge-admin-cli in a multi-DPU setup.
- [FORGE-6468](https://jirasw.nvidia.com/browse/FORGE-6468), [MR-4207](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4207): Fixed an issue with the display of machine validation states in forge-admin-cli.
- [MR-4235](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4235): Fixed an issue with the AccountLockoutThreshold value for GBx00.
- [MR-4227](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4227): Fixed an isssue with an infinite loop when there is an IO Error reading TLS certificates.
- [MR-4233](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4233): Fixed an issue where `UPDATING` Tenant state was missing.
- [MR-4232](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4232): Fixed an issue where root was hard-coded as the user on GB200s.
- [MR-4230](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4230): Fixed an issue where IOMMU is enabled in BIOS which causes the dcgmi tests to fail.
- [FORGE-6482](https://jirasw.nvidia.com/browse/FORGE-6482), [MR-4219](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4219): Fixed an issue where the health alert from automatic updates is not removed after the update is completed.
- [MR-4221](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4221):  Fixed an issue with a race condition when starting a secure-erase job for BOSS drives on a Dell server.
- [MR-4211](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4211): Fixed an issue where labels in carbide-web were not consistently sorted.
- [MR-4216](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4216): Fixed an issue where force-delete requests for machines associated with an instance type were not rejected.
- [FORGE-6466](https://jirasw.nvidia.com/browse/FORGE-6466), [MR-4208](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4208): Fixed an issue where arm64 hosts were getting stuck forever in WAITINGFORCLEANUP/HOSTCLEANUP due to reliability issues on determining if we're running on a DPU or host.
- [MR-4203](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4203): Fixed an issue where setting the BIOS password on Vikings was not enforced during ingestion.
- [MR-4189](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4189): Fixed an issue where failing jobs for erasing BOSS drives were not retried.
- [MR-4204](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4204): Fixed an issue where a wait condition message was not clear. It now reads 'Waiting for DPU to report UP. This requires forge-dpu-agent to call the RecordDpuNetworkStatus API'.
- [MR-4199](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4199): Fixed an issue where an outdated value for the commit hash was displayed in the version information in carbide-web.
- [MR-4198](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4198): Fixed an issue with state handlers misbehaving when carbide starts up before the database migration ran.

### Removed

- [MR-4218](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4218): Removed some large chunks from the aarch64 loader image which aren't needed to get the secondary image loaded.
- [MR-4191](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4191): Removed the hostname from the `forge-admin-cli mh show` command.

### Internal Changes

- [MR-4231](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4231): Faster integration tests for ssh-console.
- [MR-4229](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4229): Made integration tests run concurrently.
- [MR-4200](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4200): Added multiple instance creation retries in machine lifecycle test.
- [MR-4217](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4217): Fixed several local dev-env breakages.
- [MR-4205](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4205): Use helper methods `convert_and_log_machine_id` in `update_machine_credentials` more consistently.
- [MR-4202](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4202): Added a helper function for converting Machine IDs in handlers.
- [MR-4194](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4194): Added macros that produce `StateHandlerOutcome` values for additional debug information from state handlers.

## [v2025.06.20-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.06.06-rc3-0...v2025.06.20-rc2-0)

### Added

- [MR-4170](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4170): Added the ability to view the state of a BIOS job in the State Machine to increase visibility into the lifecycle of a failed job.
- [MR-4150](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4150): Added the ability to configure East-West Ethernet settings in Carbide.
- [MR-4151](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4151): Added the ability to manage NIC firmware versions during the DPU reprovisioning flow with a retry mechanism.
- [MR-4179](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4179): Added the ability to view the instance type name in carbide-web detail view of a machine.
- [FORGE-6238](https://jirasw.nvidia.com/browse/FORGE-6238), [MR-4110](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4110): Added Device Type to the machine capability Network to be able to identify the network interface type as DPU.
- [FORGE-4105](https://jirasw.nvidia.com/browse/FORGE-4105), [MR-3997](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3997): Added the ability to install BFB using Redfish if the BMC firmware version is version 24.10 or later.
- [FORGE-4545](https://jirasw.nvidia.com/browse/FORGE-4545), [MR-3681](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3681): Added the ability to view and toggle secure boot for an explored endpoint in carbide-web.
- [FORGE-5969](https://jirasw.nvidia.com/browse/FORGE-5969), [MR-4131](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4131): Added the ability to delete an explored endpoint in carbide-web and forge-admin-cli, using `forge-admin-cli site-explorer delete --address $BMC_IP`.

### Changed

- [MR-4166](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4166): Changed time before we consider re-resetting a host during UEFI update from 20 to 30 minutes.
- [MR-4176](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4176): Changed styling of the carbide-web UI.
- [MR-4155](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4155): Changed the boot process to use a small loader image, and a separate large root filesystem, reducing boot time from 5 minutes to 1 minute.

### Fixed

- [MR-4171](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4171): Fixed an issue where Site Explorer was incorrectly tagging machines as not allocatable because of firmware inventory 403 errors.
- [MR-4149](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4149): Fixed an issue with cloud init failing to run on user supplied cloud images.
- [FORGE-6229](https://jirasw.nvidia.com/browse/FORGE-6229), [MR-4141](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4141), [MR-4159](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4159): Fixed an issue where some machines were not supporting SHA256 PCR values by adding support for any SHA (up to 512).
- [FORGE-5974](https://jirasw.nvidia.com/browse/FORGE-5974), [MR-4165](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4165): Fixed an issue with Supermicro TPM chips that don't support AES256 encryption for communication between scout and the TPM by commonly using AES128.
- [MR-4185](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4185): Fixed an issue where the incorrect default NIC firmware was used for DOCA 2.8 (now using 32.42.1000).
- [MR-4184](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4184): Fixed an issue where API requests were failing due to an empty argument list for instance types.
- [MR-4181](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4181): Fixed an issue with error messages where nested errors would cause formatting issues.
- [MR-4180](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4180): Fixed an issue in carbide-web where empty instance types where used in search.
- [MR-4173](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4173): Fixed an issue in the state machine handling logic that could cause DPUs to reboot unexpectedly.
- [MR-4168](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4168): Fixed an issue where predicted hosts where not displayed when using `forge-admin-cli mh show`.
- [FORGE-6182](https://jirasw.nvidia.com/browse/FORGE-6182), [MR-4157](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4157): Fixed an issue where a machine would remain powered off during a restart operation in the state machine.
- [FORGE-6351](https://jirasw.nvidia.com/browse/FORGE-6351), [MR-4164](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4164): Fixed an issue where the state machine remained blocked when a machine is in state 'Waiting For Measurement' and attestation was then subsequently disabled.
- [5318791](https://nvbugspro.nvidia.com/bug/5318791), [MR-4156](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4156): Fixed an issue where DPU logs would be annotated with 'localhost' instead of the fully qualified domain name of the DPU, resulting in 'no DPU logs' alerts.
- [MR-4016](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4016): Fixed an issue where DPUs made multiple gRPC calls every 30 seconds, by consolidating the information retrieval into a single call, reducing the number of database connections and SQL queries.
- [FORGE-6301](https://jirasw.nvidia.com/browse/FORGE-6301), [MR-4126](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4126): Fixed an issue where hardware-health service would unneccessarily back-off up to a whole day if there were errors scraping health.
- [MR-4147](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4147): Fixed an issue with failing database queries for managed host network configuration.
- [FORGE-6207](https://jirasw.nvidia.com/browse/FORGE-6207), [MR-4132](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4132): Fixed an issue where NVME SSDs would become write-protected / read-only because of interrupted drive scrubbing.

### Removed

- [MR-4144](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4144): Removed old VPC peering ACL names from FNN NVUE template.
- [MR-4183](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4183): Removed the hostname from the machine overview page in carbide-web.

### Internal Changes

- [MR-4175](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4175): Added stub for rewriting of ssh-console in Rust.
- [MR-4182](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4182): Increased wait time to 3 hours after firmware downgrade in machine lifecycle tests.
- [MR-4178](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4178): Updated documentation for remoote VSCode development.
- [MR-4174](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4174): Added some post-build checks to ensure scout is functional.
- [MR-4172](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4172): Updated state machine diagram with latest assigned state changes.
- [MR-4169](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4169): Increased wait for ready state timeout in machine lifecycle tests.
- [MR-4146](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4146): Restored factory reset on Lenovos in machine lifecycle tests.
- [MR-4158](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4158): Extracted api-test helpers into a new api-test-helper crate.
- [MR-4152](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4152): Tweaked integration test  in preparation for splitting into another crate.
- [MR-4148](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4148): Added echo to unknown host instructions in ipxe for better debugging.

## [v2025.06.06-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.06.06-rc3-0...v2025.06.06-rc4-0)

### Fixed

- [MR-4153](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4153): Fixed an issue where DPU installations become very slow if there are existing failed DPU BMC tasks by only adding certificate tasks when they are not in the database.

### Removed

- [MR-4160](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4160): Removed LLDP due to DPU agent startup issues when LLDP was not configured in an environment.

## [v2025.06.06-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.06.06-rc2-0...v2025.06.06-rc3-0)

### Added

- [MR-4139](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4139): Added the ability to automatically identify the BFB firmware to copy when using `forge-admin-cli site-explorer copy-bfb-to-dpu-rshim` with automatic appending of the BFB configuration.

## [v2025.06.06-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.05.23-rc3-0...v2025.06.06-rc1-0)

### Added

- [FORGE-6113](https://jirasw.nvidia.com/browse/FORGE-6113), [MR-4023](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4023): Added the ability to use firmware definitions with multiple files.
- [FORGE-16](https://jirasw.nvidia.com/browse/), [MR-3905](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3905): Added the ability to quarantine hosts so that they are isolated from the network.
- [MR-4106](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4106): Added the ability to enable tracing logs and view them from Grafana Tempo.
- [MR-4129](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4129), [MR-4123](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4123): Added the ability to update DPUs with DOCA versions older than DOCA 2.5 using SSH.
- [MR-4102](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4102): Added the ability to interact with a DPUs BMC through SSH in Carbide.
- [MR-4097](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4097): Added the ability to view authentication logs on DPUs using Grafana.
- [MR-4099](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4099): Added the ability to secure erase BOSS drives in Dell servers as part of host cleanup in the state machine.

### Changed

- [FORGE-6177](https://jirasw.nvidia.com/browse/FORGE-6177), [MR-4111](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4111): If a BMC forgets about an update task, go back to retrying the update.

### Fixed

- [FORGE-6253](https://jirasw.nvidia.com/browse/FORGE-6253), [MR-4114](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4114): Fixed an issue where LLDP was disabled on DPUs.
- [MR-4137](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4137): Fixed an issue with setting the BMC password on Vikings with BIOS versions 1.6.7.
- [MR-4128](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4128): Fixed an issue where running iPXE was failing with Supermicro grace/grace servers because of iPXE trying to stop a driver which was already stopped.
- [FORGE-6219](https://jirasw.nvidia.com/browse/FORGE-6219), [MR-4098](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4098): Fixed an issue where querying for a missing SKU would show a database error instead of returning an empty list.
- [FORGE-6206](https://jirasw.nvidia.com/browse/FORGE-6206), [MR-4117](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4117): Fixed an issue where the last BIOS update time was not updated when setting the password using forge-admin-cli.
- [MR-4118](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4118): Fixed an issue where there was a potential for leaking passwords in logs.
- [FORGE-6223](https://jirasw.nvidia.com/browse/FORGE-6223), [MR-4103](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4103): Fixed an issue where forge-admin-cli would indefinitely retry connecting to carbide-api and display a generic error message when an expired certificate is used. The fix now handles TLS errors gracefully and prints a useful error message to the console.

### Internal

- [MR-4125](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4125): Added the ability to skip  instance creation after the ingestion during machine lifecycle tests.
- [MR-4130](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4130): Add qcow-imager for ARM64.
- [MR-4073](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4073): Added the ability to reset Dells to factory defaults in machine lifecycle tests.
- [MR-4124](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4124): Changed the ARM64 kernel version to linux-nvidia-64k-hwe-24.04 as recommended by the [MNNVL Bring-Up Guide](https://swserver.gitlab-master-pages.nvidia.com/mnnvl-bringup/deploying.html).
- [MR-4122](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4122): Added testing with multiple carbide-api instances for integration tests.
- [MR-4127](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4127): Removed the dependency on libssl.so.1.1 for forge-scout.
- [MR-4092](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4092): Added documentation about SKU validation in the Forge Book.
- [MR-4120](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4120): Changed machine vendor to a `Literal["lenovo", "dell"]` as we only support those currently.
- [MR-4109](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4109): Added running `apt-get autoclean` after a new forge-dpu version was downloaded.
- [MR-4108](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4108): Added the nvidia-imex-575 driver to ARM64 scout.

## [v2025.05.23-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.05.23-rc2-0...v2025.05.23-rc3-0)

### Added

- [MR-4099](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4099): Added logic to secure erase BOSS drives in Dell servers through redfish.

### Fixed

- [MR-4115](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4115): Fixed ManagedHostState::WaitingForCleanup handling for BOSS Drives on Dells.  Send `Reset` action to Scout only in `CleanupState::HostCleanup` and wait for the Job to be scheduled before rebooting Dells when recreating the BOSS volume after doing a secure erase.

## [v2025.05.23-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.05.09-rc2-0...v2025.05.23-rc2-0)

### Added

- [DGXH5GL3-319](https://jirasw.nvidia.com/browse/DGXH5GL3-319), [MR-4089](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4089): Added the ability to set machine update limits as a percentage of machines allowed to be unhealthy or unavailable concurrently.
- [MR-4095](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4095): Added the ability to navigate to the Grafana dashboard for the serial console log on carbide-web.
- [MR-4055](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4055): Added support for Supermicro BMC and UEFI upgrades.
- [MR-4076](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4076): Added the ability to mark DPUs as unhealthy and emit a `DpuDiskUtilizationCritical` alert when disk utilization exceeds `85%`.
- [MR-4065](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4065): Added the ability for zooming in the state machine diagram in the documentation.
- [FORGE-5978](https://jirasw.nvidia.com/browse/FORGE-5978), [MR-4034](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4034): Added the ability to handle instance network updates where users now can move the instance to a different VPC and can add or remove VFs from the instance (at the end of the interfaces list).

### Changed

- [DGXH5GL3-319](https://jirasw.nvidia.com/browse/DGXH5GL3-319), [MR-4089](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4089): Changed the default for triggering an update on instance reboot to false.
- [MR-4045](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4045): Reverted HBN back to 2.8.
- [MR-4096](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4096): Changed the forge-admin-cli command for showing VPC peering to use `show` instead of `get` to be consistent with other commands.

### Fixed

- [MR-4091](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4091): Fixed an issue where host firmware update alerts were created prematurely by ensuring alerts are now only created when the upgrade actually starts.
- [MR-4093](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4093): Fixed an issue where the `forge-admin-cli machine show` command defaulted to displaying only host machines by restoring the default to show both hosts and DPUs when no filtering flags are passed.
- [FORGE-6095](https://jirasw.nvidia.com/browse/FORGE-6095), [MR-4022](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4022): Fixed an issue where instance creation would silently fail when an operating system (OS) image would not be found by checking if the OS image exists before creating an instance.
- [MR-3808](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3808): Fixed an issue with NVUE corruption by having the Forge DPU agent manage DOCA containers, ensuring the HBN pod definition file is installed so that containers start up automatically after reboots.
- [MR-4080](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4080): Fixed an issue where the latest kernel caused general protection faults on some Dell servers by downgrading the kernel to version `6.8.0-45`.
- [MR-4074](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4074): Fixed an issue with dark mode in documentation where the state diagram would not be properly displayed on a dark background by making the background white.
- [MR-4067](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4067): Fixed an issue where the DPU agent would fail due to the bfvcheck command timing out after 10 seconds by increasing the timeout duration.
- [MR-4070](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4070): Fixed an issue in the documentation where the DPU state diagram was not labeled properly for machine vaildation.
- [MR-4069](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4069): Fixed an issue in the documentation where the DPU state diagram was not matching the actual state machine for DpuDiscoveringState, HostInit, and DpuInit.
- [MR-4066](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4066): Fully removed outdated documentation and updated other general documentation.
- [MR-4061](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4061): Fixed an issue with the DPU configuration flow that was outdated in the documentation.

### Removed

- [MR-4078](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4078): Removed debug logging for VPC peering that was inadvertently left in during testing.
- [MR-4079](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4079): Removed `LLDP data is empty for DPU` and `update machine inventory` log entries in production to reduce noise.

### Internal

- [MR-4101](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4101): Fixed an issue where the NVIDIA driver DKSM wasn't building on Dell R750 systems as the kernel source was not available.
- [MR-4090](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4090): Refactored the machine lifecycle test script to improve readability and maintainability.
- [FORGE-6211](https://jirasw.nvidia.com/browse/FORGE-6211), [MR-4094](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4094): Fixed an issue in DPU builds where files were downloaded multiple times in local builds by using `wget` instead of `curl`.
- [MR-4088](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4088): Added cleanup functions to the development environment test.
- [MR-4087](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4087): Added ipmitool support in tests for interacting with DPUs with BMC versions 23.09 and below (DOCA 2.2).
- [MR-4085](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4085): Added the ability for downgrading DPUs and related configuration to support testing of DOCA 2.2.0 and 2.2.1 on Bluefield-3 DPUs.
- [MR-4084](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4084): Added the ability to include the site name in test result snippets for better context.
- [MR-4083](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4083): Updated libredfish version to [v0.29.42](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/releases/0.29.42).
- [MR-4082](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4082): Fixed an issue with long build times for the documentation where it was unneccessarily building the boot artifacts.
- [MR-4081](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4081): Fixed an issue where documentation was overwritten by the CI pipeline of a branch by only building the documentation from the `trunk` branch.
- [MR-4019](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4019): Refactored scout to be a .deb file that can be used for installation / re-installation in the host scout image, enabled nvssh on host image, renamed the build targets to differentiate arm host from bfb builds, added the generic ability to cross-compile carbide components.
- [MR-4071](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4071): Fixed an issue where the system occasionally failed to progress from `HostInit` to `Ready` state within 2.5 hours by increasing the timeout for tests to 3 hours.
- [MR-4068](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4068): Added support for MLT tests in QA2.
- [MR-4064](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4064), [MR-4063](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4063), [MR-4062](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4062): Updated mermaid to version 11.6.
- [MR-4059](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4059): Refactored firmware test configuration in machine lifecycle tests.

## [v2025.05.09-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.04.25-rc2-0...v2025.05.09-rc2-0)

### Added

- [MR-4046](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4046): Added UFM Explorer to carbide-web.
  - UFM Explorer is a new page in carbide-web that allows to send raw HTTP GET requests to UFM in order to explore and debug its state.
  - Accessible using the `/admin/ufm-browser` path
  - Utilizes the Credentials in Carbide, and thereby avoids operators having to fetch UFM credentials from Vault in order to perform debugging.
- [MR-4041](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4041): Added links from IB Partition, Instance, Network Security Group, and VPC summary pages to their respective tenant pages.
- [MR-4039](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4039): Adding a script to the scout image to recover from a potential issue with read-only NVMe drives.
- [MR-4029](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4029): Added support for machine validation testing of GB200 systems.
- [MR-4027](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4027): Added support for machine validation testing of A100 965-24387-0004-000 systems.
- [MR-3991](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3991): Added the ability to automatically set a `HostUpdateInProgress` health alert when starting DPU or Host reprovisioning using the new `--update-message` parameter in forge-admin-cli.
- [MR-3985](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3985): Added additional debug logs in get_pxe_instruction_for_arch to help with debugging issues.
- [FORGE-6013](https://jirasw.nvidia.com/browse/FORGE-6013), [MR-3969](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3969): Added the ability to configure a timeframe for sites in which they will skip needing a manual reboot request for upgrades. Under the firmware_global section of their config, set both instance_autoreboot_period_start and instance_autoreboot_period_end with RFC 3339 style timestamps.
- [MR-3842](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3842): Added support for updating network configurations of instances.

### Changed

- [MR-4038](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4038): Changed Infiniband configuration to require **explicit** enabling instead of implicit enabling to be consistent with other Forge settings.
- [MR-4012](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4012): Changed Infiniband monitoring configuration for IbFabricMonitor to be automatically enabled when IB support is enabled, removing the need for separate configuration.
- [MR-4008](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4008): Changed DPU provisioning to automatically set both ports into Ethernet mode.
- [MR-4003](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4003): Changed the DPU HBN version to 2.9.2, including accompanying BFB and BMC firmware.
- [MR-3993](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3993): Changed VPC peering creation command to use simpler positional arguments instead of named parameters.

### Fixed

- [FORGE-6106](https://jirasw.nvidia.com/browse/FORGE-6106): Dell HGX100 (XE9680) stuck during ingestion.
  - [MR-325](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/merge_requests/325): Changed libredfish to version 0.29.38.
- [MR-4048](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4048): Only apply ForceRestart to Lenovo SR 675s with UEFI version 7.10 and BMC version 9.10 to avoide stuck terminations.
  - [MR-324](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/merge_requests/324): Changed libredfish to version 0.29.37.
- [MR-4040](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4040): Fixed an issue where machines referenced on the attestation page were not clickable by adding direct links to their machine details pages.
- [MR-4024](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4024), [MR-3990](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3990): Fixed an issue where the DPU agent was not properly loading the ATF/UEFI on old DPUs where the UEFI db was deleted.
- [MR-4017](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4017): Fixed an issue where the web UI would not redirect the user to the originally requested page after OAuth2 authentication flow.
- [MR-4014](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4014): Fixed an issue where site exploration would fail on Viking systems when changing the BMC password by using a vendor-specific Redfish client that properly handles password changes.
- [MR-4013](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4013): Fixed an issue where VPC peerings were not being deleted when their associated VPC was deleted.
- [MR-4009](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4009): Fixed an issue with the scout image that prevented proper disovery of GB200 nodes.
- [MR-4005](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4005): Fixed an issue where the network configuration  was not correctly updated when only network segment id was sent in an API request.
- [MR-4001](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4001): Fixed an issue where ntpsec service would fail to restart on DPUs after the name changed to ntpsec@mgmt.
- [MR-3998](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3998): Fixed an issue where DPUs were incorrectly booting to scout OS when no MachineId was present.
- [MR-3975](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3975): Fixed an issue where IB status changes were not immediately reflected in the state handler.

### Removed

- [MR-3987](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3987): Removed legacy maintenance mode storage from the database.

### Internal Changes

- [MR-4050](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4050): Moved IB links into their own menu section.
- [MR-4049](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4049): Fixed an issue in the test_metrics_integration test.
- [MR-4035](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4035): Added Python packages git, python3.12-venv, python3-pip to aarch64 scout image.
- [MR-4033](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4033): Added missing `mkosi.postinst.chroot` content to aarch64 scout image.
- [MR-4030](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4030): Changed the driver versions of `cuda-drivers` and `nvidia-driver-{version}-open` to use the explicit version `575`.
- [MR-4025](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4025): Updated the `nvidia-fabricmanager` version to `575`.
- [MR-4018](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4018): Fixed an issue where instance handling errors would not use proper ConfigValidationErrors.
- [MR-4011](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4011): Fixed an issue where machine-a-tron was inefficiently handling DHCP requests between hosts and DPUs by implementing a direct communication channel, resulting in faster machine provisioning and more reliable network configuration.
- [MR-4007](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4007): Fixed an issue with building the documentation by removing a duplicate file entry in book/src/SUMMARY.md.
- [MR-4006](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4006): Updated libredfish to version  [0.29.36](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/releases/0.29.36).
- [MR-4004](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4004): Refactored the location of metric_utils.rs to the logging folder where most other general metric related code already resides.
- [MR-3999](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3999), [MR-3986](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3986): Performance enhancements for machine-a-tron with thousands of hosts.
- [MR-3998](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3998): Fixed an issue where DPUs in machine-a-tron were incorrectly booting to scout OS when no Machine ID was present by properly checking if the device is a DPU before initiating PXE boot.
- [MR-3995](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3995): Fixed issues to the state diagram in the documentation.
- [MR-3989](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3989): Enable the machine lifecycle test to run against site pdx-qa2.
- [MR-3988](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3988): Removed backward compatibility functions in admin-cli that were no longer needed.
- [MR-3984](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3984): Changed the versions of `linux-image` and `linux-generic` to use the meta package in scout images to no longer having to update the currently explicit version number every few months as the archive expires.
- [MR-3959](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3959): Changed database interface to use PgConnection instead of Transactions to allow callers to pass either a transaction or just a simple connection, based on the use case.
- [MR-3547](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3547), [MR-4010](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/4010): Added support for testing auto-firmware upgrades in machine lifecycle tests.

## [v2025.04.25-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.04.11-rc1-0...v2025.04.25-rc2-0)

### Added

- [FORGE-5354](https://jirasw.nvidia.com/browse/FORGE-5354), [MR-3893](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3893): Added the VPC Peering feature to allow the creation, deletion, and search of VPC peerings. Enabled network traffic between peered VPCs based on the network virtualization type.
- [FORGE-5497](https://jirasw.nvidia.com/browse/FORGE-5497), [MR-3964](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3964): Added the ability to view Instance Types in carbide-web.
- [MR-3961](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3961): Added the ability to retrieve all VPC peerings or obtain peerings by ID in forge-admin-cli.
- [MR-3956](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3956): Added the ability to view available DPU NIC Firmware versions in the carbide-web user interface on the configuration page.
- [MR-3942](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3942): Added the ability to view Machine State History for deleted Machines via a new FindMachineStateHistories gRPC endpoint and a carbide-web URL `/admin/:machine_id/state-history`.
- [MR-3946](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3946): Added the ability to check CPU threads for SKUs to ensure accurate reporting, especially on DGX systems where threads may be disabled by default.
- [MR-3945](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3945): Added the ability to pass the MQTT server address via DHCP option 224 in carbide-dhcp for upcoming DPA provisioning work described in [DPA Underlay Configuration via DHCP](https://docs.google.com/document/d/1KABBIfhFQCT84IqIrmNgBoo-u4MZzZ418SSlFF2uwYI).
- [MR-3928](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3928): Added the ability to manage instance types in forge-admin-cli and API queries, including CRUD support for instance types, extended output fields, and filtering.
- [FORGE-4932](https://jirasw.nvidia.com/browse/FORGE-4932), [MR-3887](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3887): Added the ability to view attestation statuses for all machines in a site and access detailed attestation information for individual machines through the carbide-web UI.
- [MR-3936](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3936): Added the ability to use `machine show` in forge-admin-cli during early discovery of machines (before pairing of host and DPU) to ensure correct polling of status in Machine Lifecycle Test.
- [MR-3826](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3826): Added the ability to find the closest partially matching bundle to a report for measured boot.
- [MR-3962](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3962): Added the ability to list DPUs by machine ID in the ["DPU Logging" dashboard](https://ngcobservability-grafana.thanos.nvidiangn.net/d/eejqgu1jm76rkf/dpu-logging?orgId=1) and added `machine_id` to `telemetry_stats_log_records_total` metric so it can be used in `no-dpu-logs-warning` alerts as well as the mentioned dashboard.

### Fixed

- [MR-3950](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3950): Fixed an issue where carbide-web would show an empty page for internal server errors (500) by displaying the API error in the body to help users understand the actual issue.
- [MR-3963](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3963): Fixed an issue where the scout.efi image was not copied into the aarm64 container, causing ARM hosts to incorrectly use carbide.efi, by ensuring the scout image is available and correctly picked during the boot process.
- [MR-3953](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3953): Fixed an issue where the thread count was reported incorrectly (CPU count was displayed).
- [MR-3906](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3906): Fixed an issue where the root partition of a DPU could become full by adding a cron job for `apt clean`. Additionally, introduced a new capability to the dpu-agent to manage and sync files on the DPU with idempotency features.
- [MR-3944](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3944): Fixed an issue where setting the boot order prior to rebooting Supermicro servers caused an error if the state machine was currently configuring the BIOS or boot order.
- [MR-3938](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3938): Fixed a performance issue in carbide-web by preventing the fetching of managed host history from the database when displaying the HTML view, as it is only needed for the JSON data.
- [MR-3941](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3941): Fixed an issue where VPC peering between `ETHERNET_VIRTUALIZER` and `ETHERNET_VIRTUALIZER_WITH_NVUE` was not permitted when NVUE is enabled, by allowing this peering when `vpc_peering_policy` is set to "exclusive".
- [MR-3927](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3927): Fixed an issue with ingestion of Vikings that do not have `CPLDMB_0` version `0.2.1.9` by preventing their ingestion alltogether (as they would first require a physical power drain). Additionally, only issue an AC power cycle during preingestion for Lenovo servers, while using a regular power cycle for other server vendors.
- [MR-3923](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3923): Fixed an issue with booting from the network in GPU nodes with multiple DPUs where booting from the first slot was unreliable by ensuring Carbide always specifies the `boot_interface_mac` when configuring the boot order on hosts.
- [MR-3954](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3954): Fixed an issue where the new config in `UpdateInstanceConfig` requests was not logged by adding logging for this request data.
- [MR-3935](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3935): Improved performance of machine and managed host snapshot queries by replacing Common Table Expressions (CTEs) with subselects and adding relevant indexes, significantly reducing query time from 200-300ms to 2-3ms.

### Internal Changes

- [FORGE-5916](https://jirasw.nvidia.com/browse/FORGE-5916), [MR-3924](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3924): Improved snapshot loading by moving it up another level, allowing it to be used across all modules.
- [FORGE-5883](https://jirasw.nvidia.com/browse/FORGE-5883), [MR-3930](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3930): Added debug logs in `bf.cfg` to assist with reproducing [FORGE-5883](https://jirasw.nvidia.com/browse/FORGE-5883) as suggested in [NVBUG 5208597](https://nvbugspro.nvidia.com/bug/5208597).
- [MR-3965](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3965): Fixed an issue where site explorer fixtures were using excessive stack space by placing certain highly-used Futures on the heap and replacing RefCell with Mutex to make TestEnv Send+Sync as per the [Slack discussion](https://nvidia.slack.com/archives/C02RKLCN8BT/p1745455867937049).
- [MR-3960](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3960): Fixed an issue where carbide would write a power cycle log event even though the power cycle did not happen during NIC mode changes.
- [MR-3955](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3955): Fixed an issue where integration tests could run indefinitely by reducing the API refresh interval to 500ms, half of the machine state controller interval, and introducing a timeout for wait_until_machine_up_with_api_state.
- [MR-3949](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3949): Fixed a deadlock in bmc-mock when used in machine-a-tron by sharing the mock machine's power state with bmc-mock, eliminating the need to call into MachineStateMachine to respond to redfish calls.
- [MR-3937](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3937): Fixed an issue where VPC peer ACL did not specify their type.
- [MR-3910](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3910): Updated libredfish from version [v0.29.18](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/releases/v0.29.18) to version [0.29.32](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/releases/0.29.32).
- [MR-3466](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3466): Added the ability to build PowerDNS with a Dockerfile and provided configuration files for using PowerDNS in a local development environment.
- [MR-3929](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3929): Increased the default number of machines created per run from 1 to 4.
- [MR-3926](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3926): Updated the documentation for the web UI to include 'system account' authentication and Argo details.
- [MR-3925](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3925): Fixed an issue where an extraneous call to forge_setup was made when handling host lockdown by removing the redundant call, as it is done earlier in the ingestion process.
- Carbide will store InstanceNetworkStatusObservation in `machines` table into respective DPU row. Previously carbide used to store it in `instances` table.

## [v2025.04.11-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.04.11-rc3-0...v2025.04.11-rc4-0)

### Fixed

- [MR-3935](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3935): Improved perfomance of query which loads machine snapshots.

## [v2025.04.11-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.04.11-rc2-0...v2025.04.11-rc3-0)

### Fixed

- [MR-3953](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3953): Fixed reporting of thread count.

## [v2025.04.11-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.04.11-rc3-0...v2025.04.11-rc4-0)

### Fixed

- [MR-3935](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3935): Improved perfomance of query which loads machine snapshots.

## [v2025.04.11-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.04.11-rc2-0...v2025.04.11-rc3-0)

### Fixed

- [MR-3953](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3953): Fixed reporting of thread count.

## [v2025.04.11-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.03.28-rc1-0...v2025.04.11-rc2-0)

### Added

- [MR-3912](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3912): Added the ability to perform NVLink-based GPU-to-GPU communication testing in Hopper GPUs.
- [MR-3902](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3902): Added the ability to view health/unhealthy status in forge-admin-cli via the command `forge-admin-cli mh show`. The first column of the tabular output now indicates a healthy machine with `H` and an unhealthy machine with `U`.
- [FORGE-5839](https://jirasw.nvidia.com/browse/FORGE-5839), [MR-3897](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3897), [MR-3865](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3865): Added support for storage devices in SKU validation:
  - Adds a schema version to SKUs. Old SKUs will continue to work but cannot be created. Only new SKUs with storage info can be created.
  - Moves SKU data (CPU and GPU) to be compatible with capabilities.
  - Only uses physical storage devices in SKUs (a previous version of storage support had issues with virtual devices and disk partitions).
- [FORGE-5736](https://jirasw.nvidia.com/browse/FORGE-5736), [MR-3867](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3867): Added details to the `forge-admin-cli sku show` command when using the `--extended` option and added a new `forge-admin-cli sku show-machines` command that displays machine IDs associated with a SKU. Also, added this information to the SKU Detail section in carbide-web.
- [FORGE-4412](https://jirasw.nvidia.com/browse/FORGE-4412), [MR-3815](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3815): Added the ability for the state machine to verify if a `ForceRestart` was initiated by checking the BMC logs of the machine for relevant signals and re-issue another `ForceRestart` if these signals are absent.
- [MR-3901](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3901): Added a machine validation test to check if all NVMe drives are writable.

### Changed

- [MR-3571](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3571): Changed the arguments of `forge-admin-cli` to use `update-os` with a full JSON payload when updating an instance instead of providing an iPXE script and user data. This change supersedes [MR-3554](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3554).
- [FORGE-5876](https://jirasw.nvidia.com/browse/FORGE-5876), [MR-3889](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3889): Changed the ingestion workflow to issue an NVRAM clear (BIOS factory reset) for Vikings when the BMC and its Redfish endpoint become unresponsive, as per the recommendation of the DGX team.
- [MR-3848](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3848): Host firmware updates no longer require manual flagging in forge-admin-cli for instances and a health alerts are created when they need updating.

### Fixed

- [FORGE-5893](https://jirasw.nvidia.com/browse/FORGE-5893), [MR-3907](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3907): Fixed an issue where the firmware information to be applied to machines was not updated with the latest information from the firmware inventory (firmware containers) due to a race condition.
- [MR-3911](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3911): Fixed an issue where Carbide did not detect overlapping `site_fabric_prefixes` and `deny_fixes`. Carbide will now report the invalid configuration in the logs and not start.
- [MR-3895](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3895): Fixed an issue in machine validation where hyphenated values were not allowed in arguments for tests.
- [MR-3873](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3873): Fixed an issue where a power cycle of a machine would not be consistently triggered when toggling the mode on a DPU.
- [MR-3914](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3914): Fixed an issue with the BMC component update script that caused the installer to continue running even though it encoutered errors.
- [MR-3909](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3909): Fixed a bug in manually pairing hosts with their DPUs during the ingestion process.
- [MR-3898](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3898): Fixed an issue where machine capabilities would not report the total memory capacity and DPU count.
- [MR-3868](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3868): Fixed an issue where the host would not be power cycled after a DPU firmware upgrade is completed during DPU reprovisioning.
- [FORGE-5894](https://jirasw.nvidia.com/browse/FORGE-5894), [MR-3896](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3896): Fixed an issue where we were raising unneccessary health alerts after DPU exploration on older firmware revisions where the NicMode attribute is missing in BIOS attributes.
- [FORGE-5823](https://jirasw.nvidia.com/browse/FORGE-5823), [MR-3885](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3885): Fixed an issue where password generation would generate a password that is not meeting the required complexity requirements and cause issues when setting passwords during the machine lifecycle.
- [MR-3875](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3875): Fixed an issue where site explorer would reset BMCs that were already ingested. This change prevents instances where site explorer may have issued a BMC reboot during an install.
- [MR-3877](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3877): Fixed an issue where the `forge-admin-cli redfish` subcommand fails in cases where no gRPC certificates are provided even though the redfish commands don't need them.
- [MR-3855](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3855): Fixed an issue where a site config could break NVUE config generated by the DPU agent by creating an empty ACL list in NVUE if deny_prefixes is unset and vpc-isolation is disabled.
- [MR-3882](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3882): Fixed an issue with formatting of the `version` output of `forge-admin-cli`.
- [MR-3880](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3880): Fixed an issue where rule ID uniqueness was not enforced within a network security group.
- [FORGE-5776](https://jirasw.nvidia.com/browse/FORGE-5776), [MR-3822](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3822): Fixed an issue when we were adding empty firmware definitions to the firmware inventory.
- [MR-3879](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3879): Fixed an issue with correctly setting ACLs on DPUs when Network Security Groups (NSGs) are configured.
- [MR-3884](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3884): Fixed an issue where we were not covering additional variations of BlueField 3 Card names reported by hardware.

### Removed

- [FORGE-5874](https://jirasw.nvidia.com/browse/FORGE-5874), [MR-3888](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3888): Removed the use of `product_name` when trying to determine if a DPU needs an update.

### Internal Changes

- [MR-3863](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3863): Fixed an issue where an invalid cast would prevent the creation of an operating system image.
- [MR-3872](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3872): Changed the BlueField 3 CEC Config's default flag to false to prevent the upgrade of the CEC as part of pre-ingestion.
- [MR-3900](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3900): Changed the default status for the OS image to 'Ready' unless a volume ID is specified.
- [MR-3890](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3890): Updated libredfish from version v0.29.13 to version [v0.29.18](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/releases/v0.29.18).
- [MR-3886](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3886): Fixed an issue where a restart of machine-a-tron would generate new machine info for the same MAC address instead of generating the same machine metadata after a restart.
- [MR-3913](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3913): Changed the versions of internal packages of the scout image to newer versions.
- [MR-3883](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3883): Changed the location of CPU, GPU and Storage to HardwareInfo channel through capabilities to proide a consistent view of hardware.
- [MR-3891](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3891): Fixed several issues when running machine-a-tron mocks where machine_arch was not included in the discovery infor, where NicMode/DpuMode was not properly emulated, and where BMC proxy URLs in the redfish browser were not usable.
- [MR-3881](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3881): Fixed an issue where the last attempt for matching a SKU was recored even though a maching SKU was found.
- [MR-3908](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3908): Added unit tests for carbide-web machine health page.
- [MR-3903](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3903): Added openssh to the test container, needed for accessing DPU to perform a NIC downgrade.
- [MR-3894](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3894): Added documentation for Grafana dashboard permissions.
- [MR-3871](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3871): Added a `forge-admin-cli` command to create network details in development environment.
- [MR-3878](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3878): Added `pexpect` to the machine lifecycle test container.

## [v2025.03.28-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.03.28-rc2-0...v2025.03.28-rc3-0)

### Fixed

- Removed a health alert generated by old DPU firmware not reporting NicMode

## [v2025.03.28-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.03.14-rc2-0...v2025.03.28-rc2-0)

### Added

- [FORGE-5845](https://jirasw.nvidia.com/browse/FORGE-5845), [MR-3869](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3869): Added documentation for updating the expected machines table.
- [MR-3841](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3841): Added the ability to check if BF3s are configured properly before ingesting them to the state machine.
- [MR-3854](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3854): Added a `--concurrency` option to allow testing different concurrency levels for scraping machines concurrently (currently defaults to 16). The value can be a positive integer, `default`, or `machine_count`.
- [MR-3850](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3850): Added troubleshooting documentation when adding hosts to an existing site.
- [MR-3862](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3862): Added the ability to filter instances by `inactive_devices`.
- [MR-3859](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3859): Added a new classification `StopRebootForAutomaticRecoveryFromStateMachine` in health overrides to prevent a reboot in machine state auto recovery for maintenance purposes.
- [MR-3817](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3817): Added the ability to enable the BOM validation feature on existing sites without interfering with normal operation while automating SKU assignments without user interaction. With this change we attempt to re-match machines against a sku on an interval. This allows existing sites to auto-assign SKUs to machines but not force machines into the waiting state. When `ignore_unassigned_machines` is true, the state machine will allow machines to go to the "Ready" state without a SKU, but will periodically check if there is a SKU that matches the machine.
- [MR-3844](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3844): Added the ability to upgrade DPU BMC firmware in the preingestion flow for BF3s if the currently installed version is lower than `23.10-5`.
- [MR-3839](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3839): Added machine vaildation tests for HPE P-series (DL380a Gen11).
- [MR-3830](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3830): Added the ability to run an additional API server locally on your (Linux) host, outside of Kubernetes, for better testing capabilities.
- [MR-3831](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3831), [MR-3818](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3818): Added additional endpoinds in carbide-web to display raw JSON data for various objects:
  - `/admin/ib-partition/:partition_id.json`: Shows the content of the `IBPartition` gRPC object for the given Partition ID.
  - `/admin/instance/:instance_id.json`: Shows the content of the `Instance` gRPC object for the given Instance ID.
  - `/admin/interface/:interface_id.json`: Shows the content of the `MachineInterface` gRPC object for the given Machine Interface ID.
  - `/admin/network-security-group/:network_security_group_id.json`: Shows the content of the `NetworkSecurityGroup` gRPC object for the given group ID.
  - `/admin/network-segment/:segment_id.json`: Shows the content of the `NetworkSegment` gRPC object for the given segment ID.
  - `/admin/sku/:sku_id.json`: Shows the content of the `Sku` gRPC object for the given SKU ID.
  - `/admin/tenant/:organization_id.json`: Shows the content of the `Tenant` gRPC object for the given tenant organization ID.
  - `/admin/tenant_keyset/:organization_id/:keyset_id.json`: Shows the content of the `TenantKeyset` gRPC object for the given tenant and keyset ID.
  - `/admin/vpc/:vpc_id.json`: Shows the content of the `VPC` gRPC object for the given VPC ID.
  - `/admin/machine/:machine_id.json`: Shows the content of the `Machine` gRPC object for a given Machine ID.
  - `/admin/explored-endpoint/:endpoint_ip.json`. Shows the content of the `ExploredEndpoint` gRPC object for a given BMC address.
- [MR-3821](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3821): Added the ability to ingest HPE servers. With this change, the following capabilities are added for HPE servers:
  - Added the ability to handle HPE special power state "Reset".
  - Added the ability to detect DPU from Chassis NetworkAdapters if the DPU is not detected from PCIe devices (HPE redfish may report none even the DPU are up running).
  - Added the ability to capture hosts in power OFF state while carbide expects the power is ON.
- [FORGE-16](https://jirasw.nvidia.com/browse/FORGE-16), [MR-3819](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3819): Added support for setting and clearing quarantine via gRPC, admin-CLI, and the web UI. Note: The DPU currently doesn't do anything with this flag yet.
- [MR-3824](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3824): Added the new machine_validation container to the auto-update job.

### Changed

- [MR-3785](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3785): Changed the reporting of `MachineValidating` state from `HostInit` to `ManagedHostState`.
- [MR-3847](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3847): Changed `PreventAllocation` classification on TOR peering alerts to be true only in cases where more than one ports are unhealthy.
- [MR-3845](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3845): Changed the display of Machine Validation Results in carbide-web for better visualization. The change includes:
  - Color coding of status fields where succeeded runs feature a green background and otherwise red.
  - Validation runs are now ordered newest to oldest.
  - The Machine ID column on the Machine page was removed as it showed the same value.
  - Moved the repeating machine validation Run ID and Test ID from each line in the table to headers where applicable.
- [MR-3825](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3825): Changed unit test output to dump the Machine Entry whenever an error is encountered in order to simplify debugging the failing tests.
- [MR-3832](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3832): Changed the version of libredfish from version 0.29.8 to version 0.29.13.
  - [f92772d](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/commits/f92772d43a8a368d258353613e165000a7090ed6): Added power-cycle option to the SystemPowerControl enum for Dell servers and DPUs.
  - [8ed55b3](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/commits/8ed55b3873366a4c8e2baedd2b01b5d91253d600): Added support for HPE ingestion.
  - [6f166cb](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/commits/6f166cbd346c446af53c3978eb7fe88501922f22): Disabled unused HPE bios attribute that was being parsed incorrectly and may be inconsistent.
  - [3b40a45](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/commits/3b40a45587c06f00fb69e074d6980eee2f3892fa): Fixed an issue to retrieve NIC mode.
  - [1610f3b](https://gitlab-master.nvidia.com/nvmetal/libredfish/-/commits/1610f3b013a9c71e1b2ff3f57990172f0f53e112): Added the ability to set NIC mode on DPUs and use OEM-specific extension to retrieve NIC mode on BF3s.
- Host firmware does not need manual selection to get flagged for upgrades.
- Host firmware updates flagged for upgrades now have a health alert.
- [MR-3892](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3892): InstanceType/Machine matching now matches InstanceType count value against the sum of counts from machine capability matches.

### Fixed

- [MR-3853](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3853): Fixed an issue where we saw a recent appearance of a large number of debug logs by changing the forge-dpu-agent log level from `debug` to `info`.
- [MR-3856](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3856): Fixed an issue in agent template where we indicated faux multiple tenant support by flattening out the template config and removing multiple tenant support.
- [MR-3852](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3852): Fixed an issue where we were echoing build scripts to stdout by default by removing `-x` in the gitlab script `dev-env-test-with-carbide.sh` and move to using the `DEBUG_JUST` environment variable, which was unset (ref [MR-3846](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3846)).
- [MR-3835](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3835): Fixed an issue where we failed to execute sync workflow to create Operating System on Site by ensuring that the OS image attribute is of type enum while inserting or updating the DB.
- [MR-3851](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3851): Fixed an issue with the display of the Machine Validation table on the Machines page by setting its width to 100%.
- [MR-3837](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3837): Fixed an issue where we were incorrectly reporting `FNN_L3` for virtualization type instead of `FNN` by fixing a cast issue of an internal enum value.
- [MR-3836](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3836): Fixed an issue with parted version incompatibilities by moving to sgdisk for correcting GPT disk labels.
- [MR-3834](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3834): Fixed an issue where hosts were excluded from display in forge-admin-cli machine show if the hosts flag isn't set.
- [MR-3833](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3833): Fixed an issue in carbide-web where security groups would not correctly display when there are none and added the option to delete security groups.
- [MR-3829](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3829): Fixed an issue where we were using the current time for `observed_at` in  `InstanceNetworkStatusObservation` instead of the Machine time in cases when a DPU does not send a timestamp.
- [MR-3827](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3827): Fixed an issue where the cpu and thread count for machine capabilities were incorrectly reported.
- [MR-3828](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3828): Fixed an issue where new health reports or DPU network status observations were rejected due to an invalid timestamp.
- [FORGE-5773](https://jirasw.nvidia.com/browse/FORGE-5773), [MR-3814](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3814): Fixed an issue where unpaired/unmanaged/discovered machines where incorrectly reporting the DPU admin interface as "unreachable BMC", when it is in fact not a BMC.
- [FORGE-5180](https://jirasw.nvidia.com/browse/FORGE-5180), [MR-3726](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3726): Fixed an issue with incorrect lockdown settings for Dell servers after upgrades and forced deletions by adding a reboot as this is required to switch the lockdown mode. Enabled system lockdown will prevent changing the boot order and cause the system to boot into an unexpected operating system.

### Removed

- [MR-3823](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3823): Removed commands that are no longer needed with new bfb build.

## [v2025.03.14-rc3-1](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.03.14-rc3-0...v2025.03.14-rc3-1)

### Fixed

- Removed a health alert generated by old DPU firmware not reporting NicMode.

## [v2025.03.14-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.03.14-rc2-0...v2025.03.14-rc3-0)

### Removed

- Removed commands no longer needed with new bfb build.

## [v2025.03.14-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.02.28-rc2-0...v2025.03.14-rc2-0)

### Added

- [MR-3811](https://gitlab-master.nvidia.com/nvmetal/carbide/-/merge_requests/3811) Added DHCP NAK support to forge-dhcp-server.
- Added metrics for machine-validation feature.
- Added BIOS profiles.  Individual sites can be set to Performance or PowerEfficiency from their carbide-api-site-config.toml, defaulting to Performance.  Details of what this means for a particular model will typically come from the base carbide-api-config.toml.  These are set by the call to machine_setup during ingestion; currently changing a site's configuration will not affect any already ingested machines.
- [FORGE-5665](https://jirasw.nvidia.com/browse/FORGE-5665) allow cli to override id of sku
    allows setting the id on either the create or generate call to avoid having to manually edit the json file.

    ```
    ❯ forge-cli local sku create ~/sku-dev3.json -i dev3-sku
    +----------+----------------------------------------------+-----------------------+-----------------------------+
    | ID       | Description                                  | Model                 | Created                     |
    +==========+==============================================+=======================+=============================+
    | dev3-sku | ProLiant DL380a Gen11; 2xCPU; 0xGPU; 256 GiB | ProLiant DL380a Gen11 | 2025-03-07T19:03:27.633979Z |
    +----------+----------------------------------------------+-----------------------+-----------------------------+

    ❯ forge-cli local sku g fm100htv4fu8fpktl0e0qrg4dl58g2bc2g7naq0l6c15ruc22po1i5rfsq0 -i gen-sku
    ID:              gen-sku
    Description:     PowerEdge R760; 2xCPU; 0xGPU; 256 GiB
    Model:           PowerEdge R760
    Architecture:    x86_64
    Created At:      2025-03-07T19:04:31.084215485Z
    ...
    ```

    other wide the generated id looks like:

    ```
    ❯ forge-cli local sku g fm100htv4fu8fpktl0e0qrg4dl58g2bc2g7naq0l6c15ruc22po1i5rfsq0
    ID:              PowerEdge R760 2025-03-07 19:14:11.228991270 UTC
    ...
    ```

- [FORGE-5471](https://jirasw.nvidia.com/browse/FORGE-5471) Machines are marked as unhealthy if DPU-agent is not updated within 1 day of the site controller software deployment.
- forge-admin-cli can now use templates to easily apply pre-defined health overrides.

  ```
  ❯ admin-cli demo2 machine health-override add --help
    Insert a health report override

    Usage: forge-admin-cli machine health-override add [OPTIONS] <--health-report <HEALTH_REPORT>|--template <TEMPLATE>> <MACHINE_ID>

    Arguments:
      <MACHINE_ID>

    Options:
          --health-report <HEALTH_REPORT>  New health report as json
          --template <TEMPLATE>            Predefined Template name. Use host-update for DPU Reprovision [possible values: host-update, internal-maintenance, out-for-repair, degraded, validation, suppress-external-alerting, mark-healthy]
          --message <MESSAGE>              Message to be filled in template.
          --replace                        Replace all other health reports with this override
          --print-only                     Print the template that is going to be send to carbide
          --extended                       Extended result output.
      -h, --help                           Print help
  ```

- [FORGE-5585](https://jirasw.nvidia.com/browse/FORGE-5585) The Machine Validation Test Control feature provides flexible configuration options to manage test execution through TOML configuration files (carbide-api-site-config.toml). This enhancement allows administrators to globally control test execution states while maintaining the ability to override specific tests.
  - The feature introduces two new configuration fields under machine_validation_config.
    - test_selection_mode
    - tests

    ```
    [machine_validation_config]
    enabled = true

    # Optional: Controls global test execution behavior (Default/EnableAll/DisableAll)
    test_selection_mode = "EnableAll"
    # Optional: Override specific test states
    tests = [
        { id = "forge_MmMemLatency", enable = false },
        { id = "forge_FioSSD", enable = true }
    ]
    ```

- BMC and CEC FW are now updated during bfb installation, using the interegrated bfb firmware package.
- Added support for Dell XE9680 in machine validation.
- Host health status is recorded over time in health history. Whenever the health status (added/removed/changed alert or success) of a host changes, a new host health history record is created. Host health history can be retrieved via the `FindMachineHealthHistories` gRPC API.
- The Host Health page on carbide-web have been improved:
  - Host health history is presented directly on the health page (`/admin/machine/:id/health`), as well as on a dedicated health history page (`/admin/machine/:id/health-history`)
  - The layout of the health page had been improved
  - The list of health overrides now shows the full override definition in JSON format in an expandable `Details` column
  - The health page is now loading without an error even in case the machine is not currently ingested. This allows viewing the health history for deleted machines
- IPv4 egress rules for Network Security Groups are now stateful by default, and the behavior can be turned off in the site-controller config by setting `stateful_acls_enabled` to false under `network_security_group` config.

### Changed

- Host health status is recorded over time in health history. Whenever the health status (added/removed/changed alert or success) of a host changes, a new host health history record is created. Host health history can be retrieved via the `FindMachineHealthHistories` gRPC API.
- The Host Health page on carbide-web have been improved:
  - Host health history is presented directly on the health page (`/admin/machine/:id/health`), as well as on a dedicated health history page (`/admin/machine/:id/health-history`)
  - The layout of the health page had been improved
  - The list of health overrides now shows the full override definition in JSON format in an expandable `Details` column
  - The health page is now loading without an error even in case the machine is not currently ingested. This allows viewing the health history for deleted machines
- [FORGE-5695](https://jirasw.nvidia.com/browse/FORGE-5695) SKU auto matching now occurs when ignore_unassigned_machines is true
- IPv4 egress rules for Network Security Groups are now stateful by default, and the behavior can be turned off in the site-controller config by setting `stateful_acls_enabled` to false under `network_security_group` config.
- The handling of VPC-isolation behavior has been moved to the DPU agent.  `deny_prefixes` and `site_fabric_prefixes` are now sent separately to the DPU along with `vpc_isolation_behavior`, and the agent adjusts generated config as appropriate.  The old protobuf field has been renamed and is still populated with the original content for backward-compatibility.
- Network security group names can now be re-used between tenants.
- Updated libredfish to 0.29.8
  - Uses new functionality to query nic mode on DPUs and whether infinite boot is enabled on hosts. Deprecate querying for HttpDev1Interface on Dells--this was not being used anywhere.
  - Fixed ability to set the boot order on Dell XE9680.
- Upgrade of host firmware can now be requested of assigned instances in a similar manner to DPU upgrades.  We flag machines we want to be updated with "forge-admin-cli host reprovision set --id MACHINEID".  The tenant can the request the host to be rebooted which will trigger the actual update.  If DPU updates were requested as well, they will be performed first.

### Fixed

- Machine state is checked more often to avoid race with state machine.
- Only require bmc exploration requests to specify the BMC IP.  If the BMC mac is not specified, query the machine interface addresses table to find the MAC address associated with that IP if an entry exists in the table.
- [FORGE-5521](https://jirasw.nvidia.com/browse/FORGE-5521) increased TPM_PT_MAX_AUTH_FAIL to 256 to avoid TPM lockout during continous reingestion.
- Fixed update_machine_validation_results_completed trigger as part of [machine-validation] testing.
- [FORGE-4412](https://jirasw.nvidia.com/browse/FORGE-4412) Added proto file linter to CI pipeline and fixed existing violations.
- Site fabric prefixes are now separated from deny_prefixes
  - Stops site_fabric_prefixes from being combined with deny_prefixes.
    - Renames the original deny_prefixes field and continues to populate the old field with the combined set for older agents.
    - Updates the protos to add site_fabric_prefixes as a separate field in the network config that the DPU agent receives.
    - Updates the protos to send along VPC isolation behavior type to the DPU as well.
    - Updates the FNN, pre-FNN etv, and pre-NVUE etv templates to add in site_fabric_prefixes to the deny policies when necessary.
      - If a security group is applied, site_fabric_prefixes is ignored. (default deny is applied if no security group rule matches.)
- Improved consistency of Health Hash.  Corrects an issue where two health reports with different orderings of successes or alerts were compared, the health might have been different.
- Fixed an issue where `forge-dpu-agent` upgrade installed `node-exporter` and `transceiver-exporter` services but not starting them.
- Host firmware updates that have waited more than 20 minutes after a reset without seeing the version number update, will now try resetting it again.
- All DPUs will now do a complete upgrade of Firmware, Software and BMC.

### Removed

- [FORGE-5635](https://jirasw.nvidia.com/browse/FORGE-5635) Remove instance DHCP handling from carbide. Instance DHCP will be handled by DHCP server configured on DPU only.
- Removed deprecated configurations parameters dhcp-relay and dpu_dhcp_server_enabled.

## [v2025.02.28-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.02.14-rc3-0...v2025.02.28-rc2-0)

### Added

- Machine-validation results can now be viewed in the carbide-web.
- iPXE will now display why it's booting from the disk or network.
- Added Network Security Groups (NSG) support to the legacy pre-FNN network virtualization type.
- DPU nvue logs are now sent to the site log collection infrastructure.
- Bill of Material (BOM) Validation.  Validates a managed hosts reported hardware against its assigned hardware SKU.
  [FORGE-4515](https://jirasw.nvidia.com/browse/FORGE-4515)
  - The Host properties which are validated against the SKU in this release are:
    - Chassis Model
    - Chassis Architecture
    - CPU count
    - GPU vendor, model, memory and count
    - InfiniBand device count, vendors, models, and expected connectivity to the switch
  - `[bom_validation]` section added to api config
    - `enabled` enables BOM validation. defaults to `false`
    - `ignore_unassigned_machines` configures bom validation to only validate machines that have an assigned SKU. defaults to `false`.
  - New API endpoints for managing SKUs
  - New CLI commands for managing SKUs
  - New states for handling machine SKU validation
  - New health alerts for when a machine fails SKU validation.
- Added the ability to require AC powercycles for certain UEFI upgrades.
- The Machine Capabilities set that is transfered in the `capabilities` field of the `Machine` gRPC object now includes information which of the InfiniBand devices available on the Host are active (connected to a powered on Switch) and which are inactive (disconnected). The information is transferred via a `inactive_devices` property that is part of the `MachineCapabilityAttributesInfiniband` type. The `inactive_devices` list will inform Forge users which interfaces of an IB enabled Forge Instance are not required to be configured, since they are unplugged. This change is a part of the effort to improve the usability of Forge InfiniBand support on Hosts where only a subset of ports are connected.  
  **Example:** A host with 2 IB NICs where each of the NICs has the first port connected will be signaled with the following capability:

  ```
  {
    vendor: "Mellanox Technologies",
    name: "MT2910 Family [ConnectX-7]",
    count: 4,
    inactive_devices: [0, 2]
  }
  ```

- Added forge_ForgeRunBook machine-validation test disabled by default.
- New forge-admin-cli command, "machine hardware-info update". This command allows users to update a machine's hardware info in the site DB, in case data is missing like in [https://nvbugspro.nvidia.com/bug/4908711]. Currently, the command can only update GPUs, but other hardware info types will be added.
- The security settings of InfiniBand fabrics are now monitored by the "IB Fabric Monitor" task. If certain security related properties of an InfiniBand fabric (e.g. m_key) are not configured as expected, the metric `forge_ib_monitor_insecure_fabric_configuration_count` will be emitted with value `1`. The security settings that are monitored should be in place in order to provide strong isolation between various Forge Tenants using InfiniBand, as well as to protect the InfiniBand infrastructure from tenants. Once the metric is rolled out, alarming on insecure infrastructure configurations can be added. In order to suppress the alarm during site builds when insecure configuration is expected for a certain amount of time, a new configuration file parameter `[ib_config.allow_insecure` is added that is `false` by default. If fabrics are defined as insecure, then an additional metric `forge_ib_monitor_allow_insecure_fabric_configuration_count` will be emitted that can be used to suppress the security alert.
- Added forge_ForgeRunBook machine-validation test disabled by default.
- New forge-admin-cli command, "machine hardware-info update". This command allows users to update a machine's hardware info in the site DB, in case data is missing like in [https://nvbugspro.nvidia.com/bug/4908711]. Currently, the command can only update GPUs, but other hardware info types will be added. The next `discover_machine` call from scout will overwrite whatever you added to the table.
  **Usage** `forge-admin-cli machine hardware-info update gpus --machine fm100ht9482lgtmqok7csri5c8dm0oetjam6sqltv6p6a43jgq77v0hkhe0 --gpu-json-file gpus.json` The json file should be an array of objects of the following structure:

  ```
  {
    "name": "string",
    "serial": "string",
    "driver_version": "string",
    "vbios_version": "string",
    "inforom_version": "string",
    "total_memory": "string",
    "frequency": "string",
    "pci_bus_id": "string"
    }
  ```

  Pass an empty json array to remove all GPU entries.
- Upgrade of host firmware can now be requested of assigned instances in a similar manner to DPU upgrades.  We flag machines we want to be updated with "forge-admin-cli host reprovision sed --id MACHINEID".  The tenant can the request the host to be rebooted which will trigger the actual update.  If DPU updates were requested as well, they will be performed first.
- If host firmware updates have waited more than 20 minutes after a reset without seeing the version number update, they will now try resetting it again.

### Changed

- Update Rust version to 1.85.0.
- Rework carbide carbide-web to prefer machine page over managed host page.
  - Move Maintenance mode form from Managed-Host details page to Machine details page.
  - Move Machine Health page from `/admin/machine/health/:machine_id` to `/admin/machine/:machine_id/health`.
- Update opentelemetry to 0.28.
- Automated and manual DPU updates no longer place the Host into `Maintenance` mode. Instead of that, the Host that is undergoing updates is marked with a new health alert with ID `HostUpdateInProgress`.  
  The health alert uses a `target` property which describes the component that is updated. The motivation for this change is to be better able to distinguish updating Hosts from hosts that are undergoing other kinds of Maintenance - as well as to prevent race conditions that happened due to various workflows using the same `Maintenance` marker. Example of a health override that is placed by the updating Framework:

  ```
  {
    "source": "host-update",
    "observed_at": "2025-02-14T20:25:05.022649303Z",
    "successes": [],
    "alerts": [
        {
            "id": "HostUpdateInProgress",
            "target": "DpuFirmware",
            "in_alert_since": "2025-02-14T20:25:05.022658314Z",
            "message": "AutomaticDpuFirmwareUpdate//2.0.1",
            "classifications": [
                "PreventAllocations",
                "SuppressExternalAlerting"
            ]
        }
    ]
  }
  ```

  Operators can use a new `Host Update` template on the Machine Health page of the Forge Admin Web UI in order to place a simlar health override before manual DPU updates are started.  
  [Forge-4270](https://jirasw.nvidia.com/browse/FORGE-4270)
- The carbide-web `/admin/managed-host/:machine_id` page had been removed. Links to the page have been replaced with links to `/admin/machine/:machine_id`. The reason for the removal is that the `/admin/machine` page contained a superset of the information available on the `/admin/managed-host` page.

### Fixed

- Add some defense to DPU agent against a bad NSG config.
- [FORGE-4706](https://jirasw.nvidia.com/browse/FORGE-4706) Increase scout reconnect timeout.
- [FORGE-4270](https://jirasw.nvidia.com/browse/FORGE-4270) Remove application of Maintenance Mode during DPU updates.  The manual and automated DPU updates no longer use Maintenance modes but a custom health alert in order to mark Machines that have updates enqueued.
  - Manual updates (via forge-admin-cli) can be started at any time the Machine has a health alert with probe ID `HostUpdateInProgress` and a classification `PreventAllocations`. A new template for adding such an alert has been added to the carbide-web.
  - Example of a health override being placed:

  ```
  {
        "source": "host-update",
        "observed_at": "2025-02-14T20:25:05.022649303Z",
        "successes": [],
        "alerts": [
            {
                "id": "HostUpdateInProgress",
                "target": "DpuFirmware",
                "in_alert_since": "2025-02-14T20:25:05.022658314Z",
                "message": "AutomaticDpuFirmwareUpdate//2.0.1",
                "classifications": [
                    "PreventAllocations",
                    "SuppressExternalAlerting"
                ]
            }
        ]
    }
    ```

- Machine validation tests can now be marked as verified or unverified forge-admin-cli.
  - Set forge_RaytracingVk as unverfied.
- Fix updating supported platforms from dmidecode value.
- Allow System to pxe boot if machine is in Failed/MachineValidation state.
- Remove UEFI component from DPU preingestion.

### Removed

- Removed legacy state migration code.
- [FORGE-5635](https://jirasw.nvidia.com/browse/FORGE-5635) Remove instance DHCP handling from carbide. Instance DHCP will be handled by DHCP server configured on DPU only.

## [v2025.02.14-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.02.14-rc2-0...v2025.02.14-rc3-0)

### Fixed

- Remove UEFI component from DPU preingestion.
- Fixed incorrect machine validation link in machine details page.

## [v2025.02.14-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.31-rc4-0...v2025.02.14-rc2-0)

### Added

- VPC isolation behavior can now be controlled with a config file option
  `vpc_isolation_behavior`. It can be set to `mutual_isolation` or `open`.
  `mutual_isolation` is the name for the old default behavior, and is the
  default for this option if not specified. `open` disables VPC isolation inside
  the site.
- Added another health override template target
  - "Validation": Describes that a Machine is currently used for either machine or network validation.
- Added a new `flags` field to the gRPC message for `NetworkSegment` that can hold a `CAN_STRETCH` flag for any tenant network segment that can be used by multiple VTEPs (read: DPUs) in the network fabric.
- Machine validation support for lenovo 675v3 servers.
- Log `user_id` in each request span instead of separate log line.
- [FORGE-5396](https://jirasw.nvidia.com/browse/FORGE-5396) Make the UnsupportedVendor enum properly serializable.
- Display ManagedHostNetworkConfigResponse in tabular form (json and yaml also).
- Add support for network security groups.
  - Introduces `NetworkSecurityGroup` and a bunch of supporting structures.
  - Adds CRUD endpoints for working with security groups.
  - Adds an endpoint for querying NSG propagation across objects (VPCs, Instances).
  - Updates VPC and Instance tables, structs, and protos to accept and store NSG IDs for attaching NSGs during creation and update.
  - Updates the Carbide network config endpoints to provide DPU agent with NSG details if configured.
  - Updates DPU agent to plumb the new NSG details through to the NVUE template context.
  - Does NOT update the NVUE template.  Attilla will be doing that separately.
  - Does NOT cover forge-admin-cli updates to support NSG management.  That'll be a separate MR.
- Add icmp6 proto option to NSGs and has_network_security_group for nvue template.
  - Adds icmp6 as a protocol option for NSGs.
  - Sends along details to the NVUE template about whether an NSG was not applied vs applied but contains no rules.
  - Adds some extra validation to block things like icmp6 with ipv4 rules and prefixes, or the ANY protocol option with ports defined.
- Add network security group commands.
  - Adds an additional API endpoint for pulling the details of which objects (VPC/Instance) are are using to which NSGs.
  - Adds commands necessary for managing network security groups via the admin-cli.
  - Allows the forge-admin-cli to update instance and VPC config (for attaching/removing NSGs).
- Network Security Group support in API, CLI, and web UI, including creation, modification, searching, propagation status querying, querying for objects using security groups, and attaching/detaching security groups to/from VPCs and instances (API and CLI only).  VPC and instance configs have been updated to include network security group IDs, allowing them to be set on creation or update.  DPU agent template support is pending.
- Run CPU and MEM benchpress tests on host instead of container.
- Added flag to make sure scout can onboard hosts without TPM module.  Carbide allow generating machine_id from serial chasis if TPM certificate is not provided, but api rejects such hosts anyway. Added new flag `tpm_required` which defaulted to true, and if is set, current logic will still apply (TPM required), but if flag is set to `false` this means host can bypass TPM certificate verificationm enforcement.
- [FORGE-5410](https://jirasw.nvidia.com/browse/FORGE-5410) Add support for alternative carbide-web auth flow.
  - This allows programmatic access to the carbide API for external services, such as nautobot synchronization.
  - The secrets are app client credentials, similar to the one used by carbide-web itself for the oauth2 flow, which lets us manage them directly in the [Entra portal](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Credentials/appId/5ae5fa35-be8e-44cc-be7b-01ff76af5315/isMSAApp~/false) along with the other carbide-web app settings, and we can assign and revoke individual credentials to be handed out as needed.
- Display network prefix range in ns command in admin cli.
- Ability to reboot host with zero dpu's via grpc.
- Add OpenTelemetry DPU agent to renew mTLS certs.
- [FORGE-5122](https://jirasw.nvidia.com/browse/FORGE-5122) Add model filter to managed host view and update filter design.
- [FORGE-5218](https://jirasw.nvidia.com/browse/FORGE-5218) Make the explored endpoint detail page load faster.
- [FORGE-5217](https://jirasw.nvidia.com/browse/FORGE-5217) Display boot order on the explored endpoint details page.
- Add health override template for validation.
- Populate expected-machines from optional file if present
- Sort Machine InfiniBand interfaces in Admin Web UI by PCI Slot.
- Show machine-validation results in Forge admin UI.

### Changed

- InstanceType records can now have their metadata updated even when already associated with machines to align with Forge-Cloud.
- InstanceType records can now be deleted even when already associated with a machine as long as no associated machines have instances.  Machine associations will be cleaned up automatically to align with Forge-Cloud requirements.
- Stop printing unwanted logs on secondary DPU.  This fix will store the last made interface changes and update the state only when interface state is change like enable to disable, or vice versa.
- Updated libredfish to 0.29.4 for HPE server support and extending timeout for Viking H1000 servers.
- Do not preingest DPUs if they are at the BMC & CEC versions corresponding to DOCA 2.5.
- Carbide config is now redacted in gRPC response and carbide-web.
- [FORGE-5408](https://jirasw.nvidia.com/browse/FORGE-5408) The DPU agent moves the DOCA config files from /opt/forge/doca_container_configs/ to /etc/kubelet.d as opposed to having cloud-init do it.
  - Prevents an issue where NVUE was unable to startup blocking DPU startup.

### Fixed

- Deal with race condition in container based host firmware configs by reading the files on usage.
- Set the DPU's boot order prior to restarting it.
- Retain full IB fabric error in IbFabricMonitor logs.  IbFabricMonitor generates a log entry for each fabric on every iteration.  The log entry should show logs messages for errors while interacting with the fabric manager.  Since the errors have been truncated to 32 characters, the information was however not useful.
  - Example:

    ```
    2025-02-13 15:44:50.442
    level=SPAN span_id=0x4b56af00fb34e826 span_name=check_ib_fabrics fabric_metrics="{\"default\":{\"endpoints\":[\"https://10.91.66.240:443\"],\"fabric_error\":\"Failed to call IBFabricManager: \"}" num_fabrics=1
    ```

- Fix deny prefixes YAML nesting in FNN template and update test.
- [FORGE-5182](https://jirasw.nvidia.com/browse/FORGE-5182) Add `opensm` config data into `FabricMetrics` metrics.
- Do not retrieve host pf0 interface from DPUs in NIC mode.

### Removed

- The following set of metrics had been removed, due to being replaced with metrics
  with other names earlier in the `v2024.11.22` release:
  `forge_available_gpus_count`, `forge_allocatable_gpus_count`, `forge_allocatable_hosts_count`,
  `forge_assigned_gpus_count`, `forge_assigned_gpus_by_tenant_count`, `forge_hosts_in_use_by_tenant_count`
- Host health metrics no longer emit the `assigned` attribute, since it had been replaced with an
  `in_use` attribute in the `v2024.12.06` release.
- Assign SVI IP only if network segment has at least 3 IPs reserved.

## [v2025.01.31-rc4-1](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.31-rc4-0...v2025.01.31-rc4-1)

### Fixed

- Remove UEFI component from DPU preingestion.

## [v2025.01.31-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.31-rc3-0...v2025.01.31-rc4-0)

### Changed

- Updated libredfish to 0.29.2 for additional workarounds for Lenovo 675v3 bug preventing power forcerestart.

## [v2025.01.31-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.31-rc2-0...v2025.01.31-rc3-0)

### Fixed

- [FORGE-5404](https://jirasw.nvidia.com/browse/FORGE-5404) Adjust ipxe timeout
- Always configure the DPU to PXE boot before rebooting the ARM. We have observed that when we upgrade both the BMC (BF-24.07-14) and CEC fw (00.02.0182.0000_n02) on BF3s in reprovisioning, the boot order on the DPU is set to boot off the locally installed image. Then, the DPU gets stuck in FirmwareUpgrade because it never tries PXE booting after the BMC & CEC upgrades
  - Example (DPU with BMC IP 10.91.54.28 in AZ51):

  ```
  curl -k -D - --user root:'PASSWORD' -H 'Content-Type: application/json' -X GET https://10.91.54.28:443/redfish/v1/Systems/Bluefield
  {
  "@Redfish.Settings": {
      "@odata.type": "#Settings.v1_3_5.Settings",
      "SettingsObject": {
      "@odata.id": "/redfish/v1/Systems/Bluefield/Settings"
      }
  },
  ...
  "BootOrder": [
              "Boot0009",
              "Boot0000",
              ...
  }
  ...
  }
  ```

- Report the FW update type during preingestion.

## [v2025.01.31-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.31-rc2-0...v2025.01.31-rc3-0)

### Fixed

- Always configure the DPU to PXE boot before rebooting the ARM. We have observed that when we upgrade both the BMC (BF-24.07-14) and CEC fw (00.02.0182.0000_n02) on BF3s in reprovisioning, the boot order on the DPU is set to boot off the locally installed image. Then, the DPU gets stuck in FirmwareUpgrade because it never tries PXE booting after the BMC & CEC upgrades
  - Example (DPU with BMC IP 10.91.54.28 in AZ51):

  ```
  curl -k -D - --user root:'PASSWORD' -H 'Content-Type: application/json' -X GET https://10.91.54.28:443/redfish/v1/Systems/Bluefield
  {
  "@Redfish.Settings": {
      "@odata.type": "#Settings.v1_3_5.Settings",
      "SettingsObject": {
      "@odata.id": "/redfish/v1/Systems/Bluefield/Settings"
      }
  },
  ...
  "BootOrder": [
              "Boot0009",
              "Boot0000",
              ...
  }
  ...
  }
  ```

## [v2025.01.31-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.17-rc5-0...v2025.01.31-rc2-0)

### Added

- A new forge-admin-cli subcommands allows to copy machine metadata from Expected-Machines
  to Machines: Usage:

  ```
  forge-admin-cli machine metadata from-expected-machine [OPTIONS] <MACHINE>
  ```

  The optional `--replace-all` flag allows to specify whether existing Metadata on the Machine
  will be retained (default), or whether existing Metadata should be dropped in favor of
  the data on expected machines. Thereby specifying the flag will set a Machines metadata
  to the same values as for a newly discovered Machine.
- Improved unit-test coverage for Metadata on Instances, VPCs, Machines and Expected-Machines.
  Creation and Update of any of these objects will now use the same test-cases for rejecting
  invalid Metadata.
- [FORGE-2851](https://jirasw.nvidia.com/browse/FORGE-2851) Carbide now returns machine capabilities in
  snapshot data when querying for machines, and capabilities are compared when adding machines to instance types.
- A new extensible log parser for serial console logs and bmc sel logs.
- [FORGE-5325](https://jirasw.nvidia.com/browse/FORGE-5325) Support for admin VPC for FNN.
  Can be enabled in the site config file:

  ```
  [fnn]
  [fnn.admin_vpc]
  enabled = true
  vpc_vni = 60100
  ```

- Updated parameters to support FNN over admin network in managedhostnetworkconfigresponse message.
- [Machine-Validation] add support for Lenovo 655v3, 665 and 675
- Added support of RHEL OS to qcow imager, as well as ability to specify boot and efi fs uuid.
- Add types for IP prefixes and IP sets
  - `IpPrefix`: a representation of an IP prefix with the trailing bits guaranteed to be zero (neither `ipnetwork` nor `ipnet` can provide this guarantee, and technically PostgreSQL's `cidr` type requires it).
  - `IpSet`: a set type designed for IP resources, with aggregation built in and a single type to cover both address families.
  - `IpAddressFamily`: just an enum so we can construct IPv4 or IPv6 as a type.
  - `IdentifyAddressFamily`: a trait with some utility methods so we don't have to keep reimplementing the logic for "IPv6 is not supported".
- Updated the forge-admin-cli 'instance allocate' command to allow pxe script and user data,
- Site explorer will only update the BMC Admin account password and keep the factory username.
- [FORGE-5382](https://jirasw.nvidia.com/browse/FORGE-5382) Improved waitingformeasurement details in forge-admin-cli mh show output
- Improved reporting for preingestion host firmware upgrade failures, and retries for post ingestion host firmware upgrade failures.
- Show Machine Capabilities in admin UI
  With this change, we show the carbide derived set of capabilities for Machines on the /machine page of the admin web UI.
  This will make it easier to check whether the capability generation works as expected.
- Added health override template that allows operators to add new "Maintenance" health alerts with different targets. The targets are defines as follows:
  - null (no target): Describes that the host is in maintenance by Forge internal workflows. This mode is used by setting the currently existing Maintenance mode on hosts, as well as by update workflows.
  - "OutForRepair": Describes that a Machine is out for repair and requires intervention by an external party.
  - "Degraded": Describes that a Machine is still in use by a Tenant, but is known to have issues.

### Changed

- Event definitions file moved to ssh-console repo
- Rename CarbideOptions to CliOptions in admin-cli
- Refactored the pxe service to be based on the axum web framework, rather than rocket.
- Static configs for dpus moved internally to carbide from site config file.
- Updated libredfish to 0.28.8
- Updated sqlx version to 0.8.3
- Default the static-pxe-url to the carbide-pxe-url if it's not configured in the environment.
- Use inline sql queries instead of postgresql views.
- The NetworkSegment message now contains a `flags` field, which is used as a
  container for the `CAN_STRETCH` flag. This flag (or its absense) can be used
  by the UI to avoid showing the FNN-created segments to users.
- Internalize static configs for dpus. The following config values no longer apply and can be safely removed: dpu_nic_firmware_intial_update_enabled, dpu_nic_firmware_reprovision_update_enabled, and dpu_nic_firmware_update_version, and everything in dpu_models. If these values need to be set for any reason in the future, they must be prefaced with dpu_config.

### Fixed

- [FORGE-5371](https://jirasw.nvidia.com/browse/FORGE-5371) Machine name must use a minimum length of 2 characters - similar to Instance and VPC names.
- Add validation that description length is smaller or equal than 1024 bytes in order to prevent internal/database errors on overlong descriptions.
- Fix missing validations for duplicated labels during VPC creation.
- Ensure that Metadata validation in the VPC creation workflow happens before actually trying to persist metadata to the DB. This prevents the Internal Errors that will happen if overlong metadata is passed to the DB layer.
- When checking if host firmware is up to date and deciding that there is no change, we properly clean the reprovisioning request.  This prevents cerain situations of machines getting stuck in Ready.
- [FORGE-5320](https://jirasw.nvidia.com/browse/FORGE-5320) Handle null values in PowerMetrics returned by redfish with Lenovo 675 V3 servers.
- Do not update infiniband status when IB Manager is disabled.
- Wait for the cec background to complete after updating the BMC firmware on a BF3 before proceeding to update the ERoT firmware.
- Check for use_custom_pxe_on_boot to be honored for qcow imager as well as custom ipxe boot.
- Fixed Machine Lifecycle Test multi-DPU bug.
- mkosi now uses /tmp folder for output instead of git tree
- [Machine-Validation] Fixed ray tracing install issue.
- Skip fans 5/6 in Lenovo SR655 V3 OVX when creating hardware health reports.
- [dpu-agent] Modify self-upgrade command for better resiliency.
- Avoid back to back restarts of the same DPU.
- Combined MachineSnapshot's reprovision_requested and reprovisioning_requested
- Always configure the DPU to PXE boot before rebooting the ARM. We have observed that when we upgrade both the BMC (BF-24.07-14) and CEC fw (00.02.0182.0000_n02) on BF3s in reprovisioning, the boot order on the DPU is set to boot off the locally installed image. Then, the DPU gets stuck in FirmwareUpgrade because it never tries PXE booting after the BMC & CEC upgrades
  - Example (DPU with BMC IP 10.91.54.28 in AZ51):

  ```
  curl -k -D - --user root:'PASSWORD' -H 'Content-Type: application/json' -X GET https://10.91.54.28:443/redfish/v1/Systems/Bluefield
  {
  "@Redfish.Settings": {
      "@odata.type": "#Settings.v1_3_5.Settings",
      "SettingsObject": {
      "@odata.id": "/redfish/v1/Systems/Bluefield/Settings"
      }
  },
  ...
  "BootOrder": [
              "Boot0009",
              "Boot0000",
              ...
  }
  ...
  }
  ```

- [FORGE-5387](https://jirasw.nvidia.com/browse/FORGE-5387) Fix logic for infiniband/ethernet device detection.
  - Mellanox network device consists of two ports.
     port is presented as a separate network interface inside system.
     Port can be configured as IB or ETH. Single Mellanox device can have configuration when one port has IB type the other ETH type.
     Type detection is based on udev report.

     ```
     SUBSYSTEM=[net|infiniband]
     ID_PCI_CLASS_FROM_DATABASE='Network controller'
      - It is assumption for SUBSYSTEM=[net|infiniband]
     ID_PCI_SUBCLASS_FROM_DATABASE='Infiniband controller' or 'Ethernet controller'
      - because ports for VPI device can be configured in IB(1) or ETH(2) types
     ```

- Fix content-length header to work with 24.07 release, allowing the update of UEFI FW from 24.07 to 24.10.
- Report the FW update type during preingestion.

### Removed

- Removed OpenTelemetry DPU agent to renew mTLS certs.

## [v2025.01.17-rc6-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.17-rc6-0...v2025.01.17-rc7-0)

### Changed

- Updated libredfish to 0.29.2 for additional workarounds for Lenovo 675v3 bug preventing power forcerestart.

## [v2025.01.17-rc6-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.17-rc5-0...v2025.01.17-rc6-0)

### Fixed

- [FORGE-5404](https://jirasw.nvidia.com/browse/FORGE-5404) Adjust ipxe timeout
- Always configure the DPU to PXE boot before rebooting the ARM. We have observed that when we upgrade both the BMC (BF-24.07-14) and CEC fw (00.02.0182.0000_n02) on BF3s in reprovisioning, the boot order on the DPU is set to boot off the locally installed image. Then, the DPU gets stuck in FirmwareUpgrade because it never tries PXE booting after the BMC & CEC upgrades
  - Example (DPU with BMC IP 10.91.54.28 in AZ51):

  ```
  curl -k -D - --user root:'PASSWORD' -H 'Content-Type: application/json' -X GET https://10.91.54.28:443/redfish/v1/Systems/Bluefield
  {
  "@Redfish.Settings": {
      "@odata.type": "#Settings.v1_3_5.Settings",
      "SettingsObject": {
      "@odata.id": "/redfish/v1/Systems/Bluefield/Settings"
      }
  },
  ...
  "BootOrder": [
              "Boot0009",
              "Boot0000",
              ...
  }
  ...
  }
  ```

- Report the FW update type during preingestion.

## [v2025.01.17-rc5-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.17-rc4-0...v2025.01.17-rc5-0)

### Added

- Site explorer will only update the BMC Admin account password and keep the factory username.

## [v2025.01.17-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.17-rc3-0...v2025.01.17-rc4-0)

### Fixed

- Skip fans 5/6 in Lenovo SR655 V3 OVX when creating hardware health reports.

### Removed

- OpenTelemetry DPU agent to renew mTLS certificates.

## [v2025.01.17-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.17-rc2-0...v2025.01.17-rc3-0)

### Fixed

- Wait for the cec background to complete after updating the BMC firmware on a BF3 before proceeding to update the ERoT firmware.
- Fixed problem in image based OS that caused reinstall on every reboot.

## [v2025.01.17-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.20-rc5-0...v2025.01.17-rc2-0)

### Added

- Scout process on hosts now logs to serial console.
  forge ssh-console can now be used to view scout logs.
- Container image Includes forge-dhcp-server binary.
- Added ToolTree to the mkosi configs, making build more reproducable.
- Added implementation to fmt for OsImageStatus enum.
- Machine Validation includes a test for bandwidth.
- OpenTelemetry DPU agent to renew mTLS certificates.
- Forge now maintains the same set of `Metadata` for Machines as for `Instances` and `VPC`s. Machines can have an associated `Name`, `Description` and `Labels`. Machine metadata is returned in the `Metadata` field of the `Machine` message on the gRPC API. Machine Metadata is also visible on the `/admin/machine/$machine_id` page of the carbide-web as well as when using `forge-admin-cli machine show $machine_id`.
  By default the Machines `Name` will be set equivalent to the Machine ID.
  Other metadata fields are empty.
- Machine metadata can be updated using the new `UpdateMachineMetadata` API.
  The API supports the same version-based mechanism to prevent unexpected concurrent edits of Metadata as other Forge APIs.
- forge-admin-cli supports new sub-commands to update Machine metadata:
  - Show Machine Metadata

    ```
    forge-admin-cli machine metadata show fm100ht3du5nv89bcvmlc3v1jk6ff9d8icrt3afbhl9sc3d0ghnp7prv32g
    ```

  - Set the name or description of a Machine:

    ```
    forge-admin-cli machine metadata set --name NewMachineName --description NewMachineDescription fm100ht3du5nv89bcvmlc3v1jk6ff9d8icrt3afbhl9sc3d0ghnp7prv32g
    ```

  - Add a label for Machine:

    ```
    forge-admin-cli machine metadata add-label --key MyLabel NewMachineName --value MyLabelValue fm100ht3du5nv89bcvmlc3v1jk6ff9d8icrt3afbhl9sc3d0ghnp7prv32g
    ```

  - Remove labels from a Machine:

    ```
    forge-admin-cli machine metadata remove-labels --keys Key --Key2 fm100ht3du5nv89bcvmlc3v1jk6ff9d8icrt3afbhl9sc3d0ghnp7prv32g
    ```

- Forge can be configured to automatically apply Machine metadata (including labels) during Machine Ingestion. The required metadata can be inserted into the `Expected Machines` manifest that informs Forge about hardware that is expected to be found on a site. The `forge-admin-cli expected-machine` commands related to Expected Machines have been updated in order to store Metadata within the expected machines entries. The forge admin web UI will show metadata associated with expected machines within the JSON view available on `/admin/expected-machine-definition.json`.

### Changed

- Updated libredfish to 0.27.2 for SWIPAT OSS requirements.
- If TLS server certificate validation is disabled by setting flag DISABLE_TLS_ENFORCEMENT,
  client certificates will still be passed to the server.  Only used for testing purposes.
- [FORGE-5128](https://jirasw.nvidia.com/browse/FORGE-5128) Displaying additional machine validation properties as part of the forge-admin-cli command: mv tests show --extended
- Block scheduling a Machine Validation request if one is already pending.

### Fixed

- When a DHCP entry for a Machines Admin, OOB or BMC IP gets deleted, the Forge DHCP Server (KEA)
  will now get restarted in order to invalidate its cache and account for the deletion.
  This fixes a problem where the Forge DHCP Server did not serve DHCP requests for
  MAC addresses which obtained a different IP address after re-discovery by Forge (<https://nvbugspro.nvidia.com/bug/4792034>).
- The `UpdateTenantKeyset` and `DeleteTenantKeyset` APIs now return correct error codes instead of an `Internal` service error. Fixes (<https://nvbugspro.nvidia.com/bug/4682284>).
  - The `NotFound` status code is used when keyset is not found during update or deletion
  - The `FailedPrecondition` status code is used when the supplied version number is incorrect during update
- Explicitly reboot the host the first time we encounter an issue calling forge_setup.
- Fixed issue that prevented hosts in the same VPC from communicating with each other.
- Performance fixes for recent machine snapshot views.
- [FORGE-5085](https://jirasw.nvidia.com/browse/FORGE-5085) Prevent null org names in db.
- Serial console for supermicro and qcow imager kernel command for ipxe.
- When host is under lockdown, unlock perform power cycle and relock.
- DHCP packet handler now handles packets concurrent mode.

### Removed

- Removed FNN mmode from dhcp-server.

## [v2024.12.20-rc6-4](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc6-3...v2024.12.20-rc6-4)

### Changed

- Updated libredfish to 0.29.1 to workaround Lenovo 675v3 bug preventing power forcerestart.

## [v2024.12.20-rc6-3](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc6-2...v2024.12.20-rc6-3)

### Fixed

- Always configure the DPU to PXE boot before rebooting the ARM. We have observed that when we upgrade both the BMC (BF-24.07-14) and CEC fw (00.02.0182.0000_n02) on BF3s in reprovisioning, the boot order on the DPU is set to boot off the locally installed image. Then, the DPU gets stuck in FirmwareUpgrade because it never tries PXE booting after the BMC & CEC upgrades
  - Example (DPU with BMC IP 10.91.54.28 in AZ51):

  ```
  curl -k -D - --user root:'PASSWORD' -H 'Content-Type: application/json' -X GET https://10.91.54.28:443/redfish/v1/Systems/Bluefield
  {
  "@Redfish.Settings": {
      "@odata.type": "#Settings.v1_3_5.Settings",
      "SettingsObject": {
      "@odata.id": "/redfish/v1/Systems/Bluefield/Settings"
      }
  },
  ...
  "BootOrder": [
              "Boot0009",
              "Boot0000",
              ...
  }
  ...
  }
  ```

## [v2024.12.20-rc6-2](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc6-1...v2024.12.20-rc6-2)

### Added

- Site explorer will only update the BMC Admin account password and keep the factory username.

## [v2024.12.20-rc6-1](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc6-0...v2024.12.20-rc6-1)

### Fixed

- skip fans 5/6 in Lenovo SR655 V3 OVX when creating hardware health reports.

## [v2024.12.20-rc6-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc5-0...v2024.12.20-rc6-0)

### Fixed

- Wait for the cec background to complete after updating the BMC firmware on a BF3 before proceeding to update the ERoT firmware.

## [v2024.12.20-rc5-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc4-0...v2024.12.20-rc5-0)

### Fixed

- If a managed host doesn't have Infiniband configured, set the IB Interface state to Synced.

## [v2024.12.20-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc3-0...v2024.12.20-rc4-0)

### Added

- Handle ingestion for Bluefield 3 VPI QSFP112 2P 200G PCIe Gen5 x16

## [v2024.12.20-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc2-0...v2024.12.20-rc3-0)

### Added

- Added InstanceType implementation and handlers for CRUD actions
- Added vpc-prefix subcommand in forge-admin-cli

### Fixed

- Make the hardware health service accept both http1 and http2 connections again,
  to stop the hardware health container from crashing every 15 minutes.
- When a machine gets moved out of maintenance mode for other reasons than the `SetMaintenance` API being called
  (e.g. during firmware updates), the `Maintenance` health alert now will be properly removed.

## [v2024.12.20-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc1-0...v2024.12.20-rc2-0)

### Added

- The InfiniBand fabric monitor task will now emit 2 additional metrics:
  1. `forge_ib_monitor_ufm_partitions_count`: The amount of partitions/pkeys visible at UFM. The number can be different from the amount of partitions created on Forge:
  - Parititons created in Forge without associated GUID will not be registered at UFM
  - Partitions created outside of Forge will be tracked by the number
  2. `forge_ib_monitor_ufm_ports_by_state_count`: The total number of ports reported by UFM, aggregated by port state (e.g. `Active`).
- Added host direct-attach drive health status to admin-cli.
- DPU Agent has been updated to support Forge Native Networking.
- Integrated VPC Prefix handling (FNN) with Instance creation workflow.
- Added information on how to obtain the UFM IP in the IB runbook.
- Added Redfish Browser Support to forge-admin-cli.
- Added support for Lenovo 655v3 and 675 server models
- The pkey resource pool metrics are now also emitted for additional IB fabrics besides `default`
- Added InstanceType related data database accessors and gRPC API handlers
- When Instances are created on Zero-DPU hosts, the network config field of the created instance can be left empty by tenants.
- CreateTenant, FindTenant, and UpdateTenant APIs are now accessible by site agent.
- When FNN is used, a unique ASN will be assigned to each DPU.
- The admin web UI now provides a visual hint for disconnected IB interfaces on the `machine` page
- Use redfish to reboot a Lenovo's BMC after upgrading the NIC fw on its DPU.

### Changed

- The InfiniBand UFM IP is now configured within the carbide site-config files
  instead of being hidden in a Vault entry. The configuration is forward-compatible
  to supporting multiple InfiniBand fabric.  
  **It requires the following entry in the
  site-config file:**

  ```
  [ib_fabrics.default]
  endpoints = ["https://1.2.3.4"] # The UFM endpoint
  pkeys = [{ start = "256", end = "2303" }] # List of pkeys used by Forge
  ```

  **The previously added `[pools.pkey]` sections needs to be removed from the site-config files, since the setting is now controlled within the `ib_fabrics` block. Carbide will reject the old configuration syntax.**
- The InfiniBand fabric monitor task will now print the endpoint address of the UFM it checks in each iteration. Example results:

  ```
  level=SPAN span_id=0x9509d58bfaa0173d span_name=check_ib_fabrics fabric_metrics="{\"default\":{\"endpoints\":[\"https://10.217.161.194:443\"],\"fabric_error\":\"\",\"ufm_version\":\"6.14.1-5\",\"subnet_prefix\":\"\",\"m_key\":\"\",\"sm_key\":\"\",\"sa_key\":\"\",\"m_key_per_port\":false}}" num_fabrics=1 otel_status_code=ok timing_busy_ns=2158292 timing_elapsed_us=33074 timing_end_time=2024-12-13T19:28:50.230282096Z timing_idle_ns=30835294 timing_start_time=2024-12-13T19:28:50.197207484Z
  ```

- Each hosts InfiniBand connection status is now updated every state controller iteration by querying UFM,
  instead of querying the connection status only once at instance creation time. Thereby the most recent connection status can be queried using the `FindMachinesByIds` API and is observable on the Web UI.
- If a Machines InfiniBand device is not connected and a tenant tries to use the device in the instance creation API, the instance creation will fail. This avoids Instances being stuck in provisioning due to the disconnected IB port.
- The NVUE template for setting the FNN configuration has been updated.
- When using the `AllocateInstance` API, the status code `FailedPrecondition` is now used when host is not available due to health.
- The internal usage of error codes has been streamlined. A new error variant `Internal` has been introduced, which gets translated to gRPC status code `Internal`.
- Unit tests now utilize the new ingestion workflow using Site Explorer instead of the legacy dpu-first ingestion workflow. They are thereby now better simulating the production environments.
- Added line number from where machine state handler returns DoNothing. This allows to diagnose reasons for stuck machines.
- Secondary DPUs are now always using the `admin` network.
- Enhanced debug statement in DPU preingestion to report expected BMC fw version.
- Release builds are used instead of debug builds for forge-dpu-agent and dhcp-server on DPUs

### Fixed

- Fixed an issue where the Machine state handler could get stuck in case Maintenance
  mode was enabled on a Machine and a `Replace` health override was present.
- Reboot the DPU up to 10 times if the secure boot query is not returning the expected fields.
- Fixed the discovery of IB devices by adding the "extra ubuntu modules" which contain
  the required drivers for the ubdated Ubuntu version.
- Allocate VPC DPU loopback IP for FNN segment only and release it on instance release.
- When VPCs are deleted, all associated Loopback IPs are released - not just the first.

### Removed

- Removed predicted host in forge-admin-cli measurement results.
- Revert DPU BMC firmware until bfb/hbn is ready.
- No longer send tenant interface info to secondary DPU.

## [v2024.12.06-rc5-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc4-0...v2024.12.06-rc5-0)

### Fixed

- Make the hardware health service accept both http1 and http2 connections again,
  to stop the hardware health container from crashing every 15 minutes.
- Remove health alert when machine moves out of maintenance mode.

## [v2024.12.06-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc3-0...v2024.12.06-rc4-0)

### Added

- Reenabled attestation when in the Ready state.

## [v2024.12.06-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.12.06-rc2-0...v2024.12.06-rc3-0)

### Fixed

- Fixed the discovery of IB devices by adding the "extra ubuntu modules" which contain
  the required drivers for the ubdated Ubuntu version.

## [v2024.12.06-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.11.22-rc2-0...v2024.12.06-rc2-0)

### Added

- The admin web UI now features a "Redfish Browser" under `/admin/redfish-browser`.
  The redfish browser allows to explore the redfish tree of any BMC connected to Forge.
  It allows site admins to query specific path of BMCs for which Forge does not provide
  any additional UI support.
  The redfish browser will automatically look up the required credentials for the BMCs,
  and send them without the user having to be aware of credentials.
  In the past Forge site admins had to use command line commands like `curl` to query
  specific redfish path. That required them to have access to Machine credentials,
  which was cumbersome and problematic from a security point of view.
- The admin web UI now shows a list of all tenants which have been registered to the site under
  `/admin/tenant`. So far Forge Cloud does not submit tenant information. Therefore the list will be empty.
- The admin web UI now shows a list of all tenant keysets under `/admin/tenant_keyset`.
- The admin web UI now shows dpu-agent version under `/admin/dpu/versions`.
- The site controller has a new "VPC prefix" resource type, which is analogous
  to a network segment in L3 VPCs.
- Create network segment if vpc_prefix_id is given and allocate IP.
- Added a new state `WaitingForNetworkSegmentToBeReady` in instance state machine handler.
- Added static topology description in [UFM runbook](https://nvmetal.gitlab-master-pages.nvidia.com/carbide/playbooks/ib_runbook.html#static-topology-configuration).
- Enabled internal RBAC enforcement and a config option to disable it.
- Added instructions on how to recreate the issuer/CA inside vault in the local dev environment.
- When maintenance mode is enabled, emit a Maintenance health alert.

### Changed

- Use paginated APIs in site admin web UI.
- When attestation is enabled,  mTLS certs are only vended if attestation succeeds.
- Update BFB FW bundle using Redfish.
- Change dpu-agent and DPU dhcp server from debug builds to release builds.
- Machine metrics that used the `assigned` label are now also emitted with an additional `in_use` label which carries the same value.
- The field "Machine Id" on the Explored Endpoints page is renamed to "Derived Machine Id".

### Fixed

- Fixed the formatting on the network segment details page of the admin web UI.
- Fixed the scout RBAC rule and checks scout for required certificates.
- Removed a potential endless loop that would cause scout to hang.
- Suppress DPU alerts for states in which the DPU is knowingly offline.
- Check serial number in the expected machines manifest against the SKU that is reported from redfish.
- Scout checks for certs expiry and regenerates the certs

### Removed

- Removed tss-esapi feature, which is no longer required to build forge-admin-cli on macOS.

## [v2024.11.22-rc6-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.11.22-rc5-0...v2024.11.22-rc6-0)

### Fixed

- Change libredfish to treat the OEM field as optional instead of mandtory.

## [v2024.11.22-rc5-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.11.22-rc4-0...v2024.11.22-rc5-0)

### Fixed

- Fixed the discovery of IB devices by adding the "extra ubuntu modules" which contain
  the required drivers for the ubdated Ubuntu version.

## [v2024.11.22-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.11.22-rc3-0...v2024.11.22-rc4-0)

### Fixed

- Verify the serial number in the expected machines table matches the SKU that is reported from redfish

## [v2024.11.22-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.11.22-rc2-0...v2024.11.22-rc3-0)

### Fixed

- Corrected the rate limit value of InfiniBand partitions

## [v2024.11.22-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.11.08-rc2-0...v2024.11.22-rc2-0)

### Added

- The BMC exploration mechanism of Site Explorer can now generate Health Alerts for already ingested Machines. Three types of alerts are emitted. All of them carry the `PreventAllocations` classification, which will prevent the Machine from being allocated by a tenant. The `target` property of each alert indicates which BMC IP exhibited the issue. That allows to distinguish between problems contacting the DPU BMC, and problems contacting the Host BMC.
  1. `BmcExplorationFailure`: This alert is emitted when the last exploration run failed for any reason.
  2. `PoweredOff`: This alert is indicated if the Host or DPU reports that its power state is not equal to `On`. The same alert was already emitted by the hardware health service. Emitting the alert from site explorer will however minimize the latency for setting the alert
  3. `SerialNumberMismatch`: This alert is emitted when the Host utilizes a different serial number than indicated by expected-machines
- Serve static pxe content from an nginx server.
- Added `reset_rate_limit` and `machines_created_per_run` to SiteExplorerConfig.
- Added a separate redfish connection establishment timeout.
- Site explorer skips ingesting hosts that Forge cannot effectively provision DPUs on.
- Added metrics to track BMC remediation taken by site explorer.
- Added additional tests as part of Machine Validation development.

### Changed

- When connections from carbide to Host BMCs are established, a timeout of 10s is now utilized for TCP connection establishment and the TLS handshake, and a timeout of 2min is utilized for performing the full request. Previous versions did only use the 2min timeout, which lead to often waiting for 2min for unresponsive BMCs.
- Several metric names change in order to match the terminology  used by Forge Cloud. The metrics are still emitted under the old name for a transitionary period. Those will be removed later. The impacted metrics and new names are:
  - `forge_gpus_total_count` (was: `forge_available_gpus_count`): The total number of GPUs available in the Forge site
  - `forge_gpus_usable_count` (was: `forge_allocatable_gpus_count`): The remaining number of hosts in the Forge site which are available for immediate instance creation
  - `forge_hosts_usable_count` (was: `forge_allocatable_hosts_count`): The remaining number of GPUs in the Forge site which are available for immediate instance creation
  - `forge_gpus_in_use_count` (was: `forge_assigned_gpus_count`): The total number of GPUs that are actively used by tenants in instances in the Forge site
  - `forge_hosts_in_use_count` (did not exist before): The total number of hosts that are actively used by tenants as instances in the Forge site
  - `forge_gpus_in_use_by_tenant_count` (was: `forge_assigned_gpus_by_tenant_count`): The number of GPUs that are actively used by tenants as instances - by tenant
  - `forge_hosts_in_use_by_tenant_count` (was: `forge_assigned_hosts_by_tenant_count`): The number of hosts that are actively used by tenants as instances - by tenant
- Update timestamps when power action is skipped.
- FNN vpc_prefix_id is included in instance allocation message.
- forge-admin-cli `measurement journal show` now shows report_id without including the `--extended` option.
- forge-admin-cli add option to `measurement journal promote` to reduce the number of commands required to promote a bundle.
- Allow site explorer to reset the BMC more frequently (up to once an hour).
- Ensured that the host is powered back on after turning it off as part of DPU provisioning
- Improved power state emulation in machine-a-tron.
- Eliminate dependency from admin to carbide-api reducing the size of the binary from 756MB to 460MB.

### Fixed

- Fixed an issue where a host would end up in a reboot loop when it entered the NVMECleanFailed state. The reboot retries are now limited to 15.
- Added a lock to avoid a race condition in measured boot.
- Will no longer power down the host on the first cycle of reboot_if_needed.
- Download root certificate for x86 from the PXE server.
- Handle processing invalid infiniband configurations.
- Fixed a crash ufmclient by setting a default CryptoProvider.
- DPU is rebooted after patching its BIOS settings.
- Extend the time we wait for the DPU to come up after rebooting it from an error state.

### Removed

## [v2024.11.08-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.10.25-rc5-0...v2024.11.08-rc2-0)

### Added

- Added instructions and additional templates to health page
- Will serve static PXE content from an nginx server when configured
- Retain history from predicted machine on final machine
- Added new fields in Domain model
- Added transceiver-exporter metrics
- Added oauth2 support to carbide-web UI
- Record response body and code for EndpointExplorationError::InvalidDpuRedfishBiosResponse
- Store and display last endpoint exploration duration
- Added CLI for external config for Machine Validation feature
- Added telemetry about the volume of logs and metrics

### Changed

- forge-dpu-agent no longer sends the legacy `NetworkHealth` health check format. It only emits the new alarm based `HealthReport` report. Since all consumers of DPU health had been updated for this before, there is no impact to users.
- Machine state history is now retained when a Machine ID gets renamed from the predicted Machine ID to the stable Machine ID. This applies only to newly ingested Machines. Machines which had been ingested in the past will still miss the DPU ingestion states in history.
- Restructured client certificate renewal and retry renewal in case of failures
- Improved error message when IB ports can not be registered at UFM
- Updated libredfish version to ingest the newer Dell servers
- Removed sending the legacy DPU Health report format
- Updated to HBN version 2.3

### Fixed

- Fixed an issue where client certificate renewal on DPUs would not be retried before certificate expiry. This issue could have applied in cases where the initial renewal attempt had failed for any reason.
- Added Azure SSO support to carbide-web to fix FORGE-4369
- Fixed the check in scout to determine if the server is a DPU or not.
- No longer generate real host machine_ids in site exploration
- Check if dmi.product_name contains "Bluefield"
- Check correct redfish error for multipart FW update
- Power cycle host if CEC doesn't support chassis reset
- Now checks power state of machine before attempting power on/off
- Configures QOS data on IB partition creation
- Recover hosts stuck in Discovered state when machine validation is disabled

### Removed

- Removed ntp service start from upgrade path
- Removed unused `otlp_endpoint` references from config

## [v2024.10.25-rc5-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.10.25-rc4-0...v2024.10.25-rc5-0)

## Changed

- Increased the length of the vpc name description fields

## [v2024.10.25-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.10.25-rc3-0...v2024.10.25-rc4-0)

## Changed

- Update libredfish version to ingest the newer Dell servers
- Improved error message when a Health override with invalid mode is added

## [v2024.10.25-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.10.25-rc2-0...v2024.10.25-rc3-0)

## Fixed

- Skip machine validation if set to disabled

## [v2024.10.25-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.10.11-rc2-0...v2024.10.25-rc2-0)

## Added

- Access to GRPC endpoints using nvinit certs now logs who made the request; search for "forge-admin-cli request from" in the logs.
- Site Explorer will reboot a DPU if it cannot query the BIOS Attributes endpoint without an error.
- Machine validation "external config files" can now be deleted (see `forge-admin-cli machine-validation external-config remove`
- The Carbide Admin UI now shows the last time Carbide rebooted a node on the Machines page.  Previously this was only on the Site Explorer explored endpoint page.
- Log the full error message whenever the health-check that is executed by IBFabricMonitor fails

## Changed

- The following set of host health related metrics gained an additional attribute `assigned` which indicates whether the host that the metric references is in an assigned state (used as an instance by a tenant):
  - `forge_hosts_health_status_count`
  - `forge_hosts_unhealthy_by_probe_id_count`
  - `forge_hosts_health_overrides_count`
  - `forge_hosts_unhealthy_by_classification_count`
- The HealthOverride mode `Override` is now called `Replace`.
  When the update is applied, all previous replace overrides will be lost.
- Admin Web UI has been improved:
  - Tables are now utilizing the full available screen width
  - On the Health details page
    - the override textbox fills the screen
    - active overrides are shown as a table
  - Health alert classifications on all pages are shown as pills
  - The explored endpoints page renders exploration errors as prettified JSON data
  - The explored endpoint details renders errors as prettified JSON, and buttons got aligned to the right
  - On the Machine Details page:
    - A new BMC section has been added, which shows the BMC details and allows
      to interact with the BMC
    - Discovery Data has been moved into a separate section
    - The Full discovery report in JSON format is shown in the discovery data section. It is collapsed by default
  - The history sections on the Machine and Network Segment details pages pretty print the previous states in JSON format
  - The instance overview table contains shows the instance names
- TPM Endorsement Keys (EK) on a machine status are now deleted when a machine is force deleted.
- Machine validation results will now be sorted by start time (ascending).
- Machine validation results formatting are greatly improved in the Admin CLI
- When interactions with the IB Fabric Manager (UFM) fail, errors are logged with a higher amount of details

## Fixed

- BMC Firmware updates will trigger a DPU reboot between BMC firmware updating and NIC firmware updating
- The `force-delete` Admin CLI command can now (again) delete standalone DPUs (i.e. DPUs that aren't known to be (or no longer) attached to a host)
- Fixed an issue where the admin web UI page for instances could not be displayed when an instance used a VF or a network interface where the MAC address was not yet reported by `forge-dpu-agent`.
- When DNS queries are issued via carbide-dns against carbide-api, the `LookupRecord` method will return a `NotFound` error code instead of an `Internal` error code. Due to this change, the carbide-api availability will no longer show up as degraded when Forge users perform queries for invalid domain names. The `NotFound` gRPC status code is transformed into a `NXDomain` DNS error code. If DNS queries fail for real internal server errors, a `ServFail` error code will be utilized.
- Fixed an issue where Carbide was incorrectly querying the status of SecureBoot in the Redfish API

## Removed

## [v2024.10.11-rc3-3](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.10.11-rc3-2...v2024.10.11-rc3-3)

### Changed

- TPM EK Certificates are now checked against a CA

## [v2024.10.11-rc3-2](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.10.11-rc3-1...v2024.10.11-rc3-2)

### Fixed

- Fixed an issue that causes machines to get stuck during DPU/Reprovisioning

## [v2024.10.11-rc3-1](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.10.11-rc3-0...v2024.10.11-rc3-1)

### Fixed

- FIxed an issue that prevented the forge-admin-cli from working with the carbide-api service

## [v2024.10.11-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.10.11-rc2-0...v2024.10.11-rc3-0)

### Added

- Now has the ability to ingest hosts other than Dell and Lenovo even if the BIOS password is not set
- Create only one machine per site explorer run

### Fixed

- Added WaitingForMeasurements state to carbide-pxe
- Modified the state machine queries for secure boot status

## [v2024.10.11-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.27-rc6-0...v2024.10.11-rc2-0)

### Added

- 2 new metrics that track the amount of Hosts and GPUs that are allocatable immediatly
  for tenant usage have been added. These complement the existing `forge_available_gpus_count`,
  `forge_assigned_gpus_count`, `sum(forge_machines_per_state{fresh="true"})` and
  `sum(forge_machines_per_state{fresh="true", state="assigned"})` metrics:
  - `forge_allocatable_gpus_count`: Tracks the amount of GPUs wich are not yet used by tenants, but which would be immediately ready for usage. This requires the underlying Machines to be in Ready state, as well as the Machine to be healthy.
  - `forge_allocatable_hosts_count`: Tracks the amount of Hosts wich are not yet used by tenants, but which would be immediately ready for usage. This requires the underlying Machines to be in Ready state, as well as the Machine to be healthy.
- A Scout Image for ARM machines is now being built to support ARM based CPUs
- The Forge Admin CLI added a `clear-nvram` functionality to help recover DGX H100 machines
- For measured boot, the signature on the measurement bundle will be checked against a trusted certificate authority.
- HPE machines can now be ingested by Site Explorer
- Explored Endpoints on the Admin UI can now clear the vault credentials
- Metrics are now generated for power consumption rate
- Added a new API for updating Operating Systems for curated images [FORGE-4277](https://jirasw.nvidia.com/browse/FORGE-4277)
- The Admin UI now has a button on an endpoint to reconfigure the UEFI settings for Forge (i.e. `forge_setup`)

### Changed

- DPU-based BGP health probes are more detailed as to what is failing the health checked:
  - `BgpPeeringTor` contains information about which ToR lost a BGP session
  - `BgpPeeringRouteServer` contains information when a session to the centralized Route Server is lost.
  - `UnexpectedBgpPeer` contains information about a peer that is unknown
  - `BgpStats` contains stats about BGP session information
- Machines in `HostInit/WaitingForDiscovery` state now have a 30 minute SLA.
- Site Explorer will only create one machine at a time to avoid a thundering herd problem.
- All hardware-health emitted metrics standardized on the prefix of `hardware_health_`.
  - This affects: `forge_hardware_health_monitor_iteration_latency`

### Fixed

- Hosts were getting repeatedly queued for updates when they were not needed.  [https://nvbugspro.nvidia.com/bug/4892326](https://nvbugspro.nvidia.com/bug/4892326)
- Mac addresses are now displayed properly in the `forge-admin-cli site-explorer` command.
- Fixed an issue with machine state handler where the machine state could be corrupted
- Additional resiliency in configuring the UEFI settings on DGX H100.

## [v2024.09.27-rc6-2](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.27-rc6-1...v2024.09.27-rc6-2)

No user facing changes.

## [v2024.09.27-rc6-1](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.27-rc6-0...v2024.09.27-rc6-1)

No user facing changes.

## [v2024.09.27-rc6-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.27-rc5-0...v2024.09.27-rc6-0)

### Fixed

- Create only one machine per site explorer run to avoid overloading the pxe server

## [v2024.09.27-rc5-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.27-rc4-0...v2024.09.27-rc5-0)

### Fixed

- Improvements in the ingestion of Viking servers

## [v2024.09.27-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.27-rc3-0...v2024.09.27-rc4-0)

### Added

- Hardware Health Monitor now emits a histogram metric `forge_hardware_health_iteration_latency_millisecons_sum`/`_count`. The metric tracks the time it takes to perform one health iteration.
- Support for Viking host firmware upgrades
- DPU ingestion will now enable the DPU BMC's rshim ([FORGE-4538](https://https://jirasw.nvidia.com/browse/FORGE-4358)).
- The Forge Admin UI gained support for running `forge_setup` on a BMC, reconfiguring the BMC for forge use on-demand

### Changed

- The following hardware health monitor metrics have been renamed and their types had been changed from Gauge to Histograms:
  - `api_findmachines_latency` => `forge_hardware_health_findmachines_latency_milliseconds_sum`/`_count`
  - `api.getbmcmetadata.latency` => `forge_hardware_health_getbmcmetadata_latency_milliseconds_sum`/`_count`
- Forge Scout now runs in a Ubuntu 22.04 image instead of Debian 12 for compatibility with NVIDIA Software for upcoming ARM support
- Force deleting a machine with an instance now requires specifying `--allow-delete-with-instance` flag.
- State machine should update db only if handler returns Success. (Fixes: [4901186](https://nvbugspro.nvidia.com/bug/4901186))

### Fixed

- Hardware Health Monitor no longer restarts when the list of Machines can no be retrieved (fixes <https://nvbugspro.nvidia.com/bug/4890909>)
- Firmware versions stored in machine_topology now get updated when site explorer runs to fix [https://nvbugspro.nvidia.com/bug/4813183](https://nvbugspro.nvidia.com/bug/4813183).
- Fixes issue that prevented hosts in the same VPC from communicating with each other.
- Fixed issue with handling nvme command drive parameters [NVBug 4892022](https://nvbugspro.nvidia.com/bug/4892022)

### Removed

## [v2024.09.27-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.27-rc2-0...v2024.09.27-rc3-0)

No user facing changes.

## [v2024.09.27-rc2-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.27-rc1-0...v2024.09.27-rc2-0)

### Changed

- Reverted: Forge scout now runs in Ubuntu 24.04 instead of Debian 12 for compatibility with ARM servers and NVIDIA drivers.

## [v2024.09.27-rc1-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.13-rc5-0...v2024.09.27-rc1-0)

### Added

- The Hardware Health monitor will emit a `PoweredOff` alert if the systems powerstate is not `On`.
  We already had a `PowerSupply` alert before which inspected the status of the redfish power subsystem. However most of our other code just looks at the top level power status which is encoded in the `ComputerSystem`. Therefore a separate alert is emitted for the value of this field.
- A new metric `forge_hosts_health_overrides_count` is emitted which indicates the amount of health overrides that are configured on a site. That allows operators to determine whether any health status might be impacted by overrides or whether hosts are "naturally" health or unhealthy.
  The metric carries an attribute `override_type` which can be either `merge` or `override`.
  **Example:**

  ```
  forge_hosts_health_overrides_count{fresh="true",override_type="merge"} 1
  forge_hosts_health_overrides_count{fresh="true",override_type="override"} 0
  ```

- The ManagedHost (`/admin/managed-host`), Machine (`/admin/host`), Network Segment (`/admin/network-segment`) and IB Partition (`/admin/ib-partition`) overview pages on the admin UI now show a ⏱️ icon if the object is in a state for longer than allowed by the SLA ("stuck").
  - The ManagedHost page also allows to filter for these Machines.
  - The details pages of ManagedHosts, Machines, NetworkSegment and IB Partitions show a flag on whether these Machines are stuck, and the actual SLA that applies for the state.
- Similar to the Machines pages, the `forge-admin-cli mh show $machineid` now shows whether a machine is in a state for longer than allowed by the SLA ("stuck").
- FORGE-3866: MultiDPU - Decide host's primary interface based on PCI Device Path. The DPU attached to primary interface will be used as primary DPU.
- The Admin UI gained the ability to reboot a BMC via RedFish or IPMI
- The Admin UI gained the ability to clear the last site explorer expiration error to indicate Site Explorer should restart exploration for a particular BMC.
- The Admin UI will now display timestamps of BMC reboot / reset timestamps.
- Carbide now supports mutual-TLS for communicating with UFM, configuration is described in [the Infiniband Runbook](https://nvmetal.gitlab-master-pages.nvidia.com/carbide/playbooks/ib_runbook.html)
- Carbide will now update the DPU BMC when going through DPU Reprovisioning states.
- DGX H100 (Vikings) are supported for host ingestion *if the UEFI firmware version is 1.5.3* (Automatic UEFI Firmware upgrades during pre-ingestion will come at a future date).
  - The DPU and host serial number pairs still must be pre-populated in Expected Machines.
- Tenants can now update instances with new Operating Systems without deleting the instance first (see [FORGE-2911](https://jirasw.nvidia.com/browse/FORGE-2911)).

### Changed

- Forge Site admin can now perform machine validation on-demand (only on Ready/Failed machines) [FORGE-4465](https://jirasw.nvidia.com/browse/FORGE-4465).
  - Use following command to trigger on-demand machine validation: `forge-admin-cli machine-validation on-demand start -m <machineID>`.
- Feature flag to enable and disable machine validation [FORGE-4487](https://jirasw.nvidia.com/browse/FORGE-4487)
- Forge scout now runs in Ubuntu 24.04 instead of Debian 12 for compatibility with ARM servers and NVIDIA drivers.
- User can now mention history count to be displayed in `machine show` command in forge-admin-cli command.

### Fixed

- Fixes redirect after Power Actions or BMC Reset have been issued on the carbide admin web UI.
- PowerStates are correctly shown on explored-endpoint details page (`/admin/explored-endpoint/IP`)
- Adds paging to network-status page in carbide-web UI to fix FORGE-4483 and prevent 5xx responses when viewing large sites.
- The Admin UI network status page uses paginated API calls and will not fail if the number exceeds the page size.
- The DPU agent will not crash if `/run` is not writable
- The DPU agent will now configure `ovs-switchd` to use less CPU

## [v2024.09.13-rc6-1](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.13-rc6-0...v2024.09.13-rc6-1)

### Fixed

- Fixes issue that prevented hosts in the same VPC from communicating with each other.

## [v2024.09.13-rc6-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.13-rc5-0...v2024.09.13-rc6-0)

No user facing changes.

## [v2024.09.13-rc5-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.13-rc4-0...v2024.09.13-rc5-0)

No user facing changes.

## [v2024.09.13-rc4-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.13-rc3-0...v2024.09.13-rc4-0)

No user facing changes.

## [v2024.09.13-rc3-0](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.09.13-rc2-0...v2024.09.13-rc3-0)

No user facing changes.

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
- Site Explorer will now emit time-series metrics for expected machines and missing machines (fixes: [FORGE-3353](https://jirasw.nvidia.com/browse/FORGE-3353))
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

## [v2024.08.30-rc3-1](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2024.08.30-rc3-0...v2024.08.30-rc3-1)

No user facing changes.

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
- Numerous updates to the carbide-web (carbide-api/admin) for sorting and usability
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
