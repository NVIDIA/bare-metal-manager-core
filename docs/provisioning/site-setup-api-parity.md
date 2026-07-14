# Site Setup API Parity

Use the REST API and `nicocli` for site setup whenever an operation is listed as covered below. Direct `nico-admin-cli` access remains necessary only for the gaps that have not yet reached the REST API.

| Site setup task | Current status | Preferred command or tracked gap |
|---|---|---|
| Store the site-wide BMC root credential | Covered | `nicocli bmc-credential create --site-id <site-uuid> --kind SiteWideRoot --password <password>` |
| Store the site-default host UEFI credential | Covered | `nicocli uefi-credential create --site-id <site-uuid> --kind Host --password <password>` |
| Store the site-default DPU UEFI credential | Covered | `nicocli uefi-credential create --site-id <site-uuid> --kind DPU --password <password>` |
| Register an Expected Machine | Covered | `nicocli expected-machine create --site-id <site-uuid> --bmc-mac-address <mac> --chassis-serial-number <serial> --default-bmc-username <user> --default-bmc-password <password>` |
| Register Expected Machines in a batch | Covered | `nicocli expected-machine batch-create --data-file expected-machines.json` |
| Approve, list, or remove measured-boot machine trust rules | Gap | Tracked by [#2801](https://github.com/NVIDIA/infra-controller/issues/2801). Use `nico-admin-cli attestation measured-boot site trusted-machine approve`, `list`, or `remove` until that issue is complete. |
| Approve, list, or remove measured-boot profile trust rules | Gap | Tracked by [#2801](https://github.com/NVIDIA/infra-controller/issues/2801). Use `nico-admin-cli attestation measured-boot site trusted-profile approve`, `list`, or `remove` until that issue is complete. |
| Clear a Site Explorer endpoint error | Gap | Tracked by [#2802](https://github.com/NVIDIA/infra-controller/issues/2802). Use `nico-admin-cli site-explorer clear-error <bmc-ip>` until that issue is complete. |
| Queue a Site Explorer endpoint for re-exploration | Gap | Tracked by [#2802](https://github.com/NVIDIA/infra-controller/issues/2802). Use `nico-admin-cli site-explorer re-explore <bmc-ip>` until that issue is complete. Bulk selection and execution also remain part of this gap. |

## Remaining parity plan

The REST/nicocli parity work is tracked under [#2852](https://github.com/NVIDIA/infra-controller/issues/2852):

- [#2799](https://github.com/NVIDIA/infra-controller/issues/2799) covers site-wide BMC and UEFI credentials and is complete.
- [#2801](https://github.com/NVIDIA/infra-controller/issues/2801) adds measured-boot trust approval operations.
- [#2802](https://github.com/NVIDIA/infra-controller/issues/2802) adds Site Explorer clear-error and re-explore operations.
- [#2803](https://github.com/NVIDIA/infra-controller/issues/2803) covers additional admin-cli inventory. Its implementation merged in [#3241](https://github.com/NVIDIA/infra-controller/pull/3241); the issue remains open for administrative closure.

After #2801 and #2802 are complete, update this table to replace the remaining direct admin-cli commands with their generated `nicocli` commands.
