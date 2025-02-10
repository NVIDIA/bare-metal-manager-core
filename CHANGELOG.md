# Changelog
## [Unreleased](https://gitlab-master.nvidia.com/nvmetal/carbide/-/compare/v2025.01.31-rc3-0...trunk)

### Added

- VPC isolation behavior can now be controlled with a config file option
  `vpc_isolation_behavior`. It can be set to `mutual_isolation` or `open`.
  `mutual_isolation` is the name for the old default behavior, and is the
  default for this option if not specified. `open` disables VPC isolation inside
  the site.
- Network Security Group support in API and CLI, including creation, modification, searching, propagation status querying, querying for objects using security groups, and attaching/detaching security groups to/from VPCs and instances.  VPC and instance configs have been updated to include network security group IDs, allowing them to be set on creation or update.  DPU agent template support is pending.

### Changed
### Fixed

### Removed
- The following set of metrics had been removed, due to being replaced with metrics
  with other names earlier in the `v2024.11.22` release:
  `forge_available_gpus_count`, `forge_allocatable_gpus_count`, `forge_allocatable_hosts_count`,
  `forge_assigned_gpus_count`, `forge_assigned_gpus_by_tenant_count`, `forge_hosts_in_use_by_tenant_count`
- Host health metrics no longer emit the `assigned` attribute, since it had been replaced with an
  `in_use` attribute in the `v2024.12.06` release.

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
- Updated the admin-cli 'instance allocate' command to allow pxe script and user data,
- Site explorer will only update the BMC Admin account password and keep the factory username.
- [FORGE-5382](https://jirasw.nvidia.com/browse/FORGE-5382) Improved waitingformeasurement details in admin-cli mh show output
- Improved reporting for preingestion host firmware upgrade failures, and retries for post ingestion host firmware upgrade failures.
- Show Machine Capabilities in admin UI
  With this change, we show the carbide derived set of capabilities for Machines on the /machine page of the admin web UI.
  This will make it easier to check whether the capability generation works as expected.
- Added health overrride template that allows operators to add new "Maintenance" health alerts with different targets. The targets are defines as follows:
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
  -  Mellanox network device consists of two ports.
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
- Forge now maintains the same set of `Metadata` for Machines as for `Instances` and `VPC`s. Machines can have an associated `Name`, `Description` and `Labels`. Machine metadata is returned in the `Metadata` field of the `Machine` message on the gRPC API. Machine Metadata is also visible on the `/admin/machine/$machine_id` page of the admin web ui as well as when using `forge-admin-cli machine show $machine_id`.
  By default the Machines `Name` will be set equivalent to the Machine ID.
  Other metadata fields are empty.
- Machine metadata can be updated using the new `UpdateMachineMetadata` API.
  The API supports the same version-based mechanism to prevent unexpected concurrent edits of Metadata as other Forge APIs.
- `forge-admin` cli supports new sub-commands to update Machine metadata:
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
  MAC addresses which obtained a different IP address after re-discovery by Forge (https://nvbugspro.nvidia.com/bug/4792034).
- The `UpdateTenantKeyset` and `DeleteTenantKeyset` APIs now return correct error codes instead of an `Internal` service error. Fixes (https://nvbugspro.nvidia.com/bug/4682284).
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

- Removed predicted host in admin-cli measurement results.
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
- admin-cli `measurement journal show` now shows report_id without including the `--extended` option.
- admin-cli add option to `measurement journal promote` to reduce the number of commands required to promote a bundle.
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
- User can now mention history count to be displayed in `machine show` command in admin-cli command.

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
