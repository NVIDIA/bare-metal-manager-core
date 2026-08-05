# Site Setup API Parity

Use the REST API and `nicocli` for the site setup operations below.

| Site setup task | Current status | Preferred `nicocli` command |
|-----------------|----------------|-------------------------------|
| Approve, list, or remove measured-boot machine trust rules | Covered | Use `nicocli measured-boot-trusted-machine create`, `list`, or `delete`. |
| Approve, list, or remove measured-boot profile trust rules | Covered | Use `nicocli measured-boot-trusted-profile create`, `list`, or `delete`. |
| Clear a Site Explorer endpoint error | Covered | Use `nicocli site-explorer create --data '{"siteId":"<site-id>","action":"ClearError","target":"EndpointIds","endpointIds":["<bmc-ip>"]}'`. |
| Queue a Site Explorer endpoint for re-exploration | Covered | Use `nicocli site-explorer create --data '{"siteId":"<site-id>","action":"ReExplore","target":"EndpointIds","endpointIds":["<bmc-ip>"]}'`. |
| Register an Expected Machine | Covered | Use `nicocli expected-machine create --data-file -` with the password-safe stdin workflow in [Add Expected Machines Table](ingesting-hosts.md#add-expected-machines-table). |
| Register Expected Machines in a batch | Covered | `nicocli expected-machine batch-create --data-file expected-machines.json` |
| Store the site-default DPU UEFI credential | Covered | Use `nicocli uefi-credential create --data-file -` with the password-safe stdin workflow in [Store Host and DPU UEFI Passwords](ingesting-hosts.md#store-host-and-dpu-uefi-passwords). |
| Store the site-default host UEFI credential | Covered | Use `nicocli uefi-credential create --data-file -` with the password-safe stdin workflow in [Store Host and DPU UEFI Passwords](ingesting-hosts.md#store-host-and-dpu-uefi-passwords). |
| Store the site-wide BMC root credential | Covered | Use `nicocli bmc-credential create --data-file -` with the password-safe stdin workflow in [Store Host and DPU BMC Password](ingesting-hosts.md#store-host-and-dpu-bmc-password). |

## Remaining parity plan

The REST/nicocli parity work is tracked under [#2852](https://github.com/NVIDIA/infra-controller/issues/2852):

- [x] [#2801](https://github.com/NVIDIA/infra-controller/issues/2801) adds measured-boot trust approval operations. Its implementation merged in [#3464](https://github.com/NVIDIA/infra-controller/pull/3464).
- [x] [#2802](https://github.com/NVIDIA/infra-controller/issues/2802) adds Site Explorer clear-error and re-explore operations. Its implementation merged in [#3432](https://github.com/NVIDIA/infra-controller/pull/3432).
- [x] [#2803](https://github.com/NVIDIA/infra-controller/issues/2803) covers site-default Host and DPU UEFI credentials. Its implementation merged in [#3241](https://github.com/NVIDIA/infra-controller/pull/3241).
