# Site Setup API Parity

Use the REST API and `nicocli` for site setup whenever an operation is listed as covered below. Direct `nico-admin-cli` access remains necessary only for the gaps that have not yet reached the REST API.

The gap commands below assume `nico-admin-cli` is configured through
`$HOME/.config/nico_api_cli.json` or the corresponding environment variables.
Without that configuration, set the variables below to the target API and
certificate paths, then supply the connection context before the command:

```bash
NICO_API_URL='https://api.example.com'
NICO_ROOT_CA_PATH='/path/to/ca.crt'
NICO_CLIENT_CERT_PATH='/path/to/client.crt'
NICO_CLIENT_KEY_PATH='/path/to/client.key'

nico-admin-cli \
  -a "$NICO_API_URL" \
  --root-ca-path "$NICO_ROOT_CA_PATH" \
  --client-cert-path "$NICO_CLIENT_CERT_PATH" \
  --client-key-path "$NICO_CLIENT_KEY_PATH" \
  --help
```

| Site setup task | Current status | Preferred command or tracked gap |
|-----------------|----------------|----------------------------------|
| Approve, list, or remove measured-boot machine trust rules | Gap | Tracked by [#2801](https://github.com/NVIDIA/infra-controller/issues/2801). Use `nico-admin-cli attestation measured-boot site trusted-machine approve`, `list`, or `remove` until that issue is complete. |
| Approve, list, or remove measured-boot profile trust rules | Gap | Tracked by [#2801](https://github.com/NVIDIA/infra-controller/issues/2801). Use `nico-admin-cli attestation measured-boot site trusted-profile approve`, `list`, or `remove` until that issue is complete. |
| Clear a Site Explorer endpoint error | Gap | Tracked by [#2802](https://github.com/NVIDIA/infra-controller/issues/2802). Use `nico-admin-cli site-explorer clear-error <bmc-ip>` until that issue is complete. |
| Queue a Site Explorer endpoint for re-exploration | Gap | Tracked by [#2802](https://github.com/NVIDIA/infra-controller/issues/2802). Use `nico-admin-cli site-explorer re-explore <bmc-ip>` until that issue is complete. Bulk selection and execution also remain part of this gap. |
| Register an Expected Machine | Covered | Use `nicocli expected-machine create --data-file -` with the password-safe stdin workflow in [Add Expected Machines Table](ingesting-hosts.md#add-expected-machines-table). |
| Register Expected Machines in a batch | Covered | `nicocli expected-machine batch-create --data-file expected-machines.json` |
| Store the site-default DPU UEFI credential | Covered | Use `nicocli uefi-credential create --data-file -` with the password-safe stdin workflow in [Store Host and DPU UEFI Passwords](ingesting-hosts.md#store-host-and-dpu-uefi-passwords). |
| Store the site-default host UEFI credential | Covered | Use `nicocli uefi-credential create --data-file -` with the password-safe stdin workflow in [Store Host and DPU UEFI Passwords](ingesting-hosts.md#store-host-and-dpu-uefi-passwords). |
| Store the site-wide BMC root credential | Covered | Use `nicocli bmc-credential create --data-file -` with the password-safe stdin workflow in [Store Host and DPU BMC Password](ingesting-hosts.md#store-host-and-dpu-bmc-password). |

## Remaining parity plan

The REST/nicocli parity work is tracked under [#2852](https://github.com/NVIDIA/infra-controller/issues/2852):

- [ ] [#2801](https://github.com/NVIDIA/infra-controller/issues/2801) adds measured-boot trust approval operations.
- [ ] [#2802](https://github.com/NVIDIA/infra-controller/issues/2802) adds Site Explorer clear-error and re-explore operations.
- [x] [#2803](https://github.com/NVIDIA/infra-controller/issues/2803) covers site-default Host and DPU UEFI credentials. Its implementation merged in [#3241](https://github.com/NVIDIA/infra-controller/pull/3241); the issue remains open for administrative closure.

After #2801 and #2802 are complete, the table on this page will be updated to replace the remaining direct admin-cli commands with their generated `nicocli` equivalents.
