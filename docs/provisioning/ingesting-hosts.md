# Ingesting Hosts

Once you have NVIDIA Infra Controller (NICo) up and running, you can begin ingesting machines.

## Prerequisites

Ensure you have the following prerequisites met before ingesting machines:

1. You have the `nico-admin-cli` command available: You can compile it from sources or you can use the pre-compiled binary. Another choice is to use a containerized version. You can also download it from the cluster; see next section for details.

2. You can access the NICo site using the `nico-admin-cli`.

3. The NICo API service is running at IP address `NICo_API_EXTERNAL`. It is recommended that you add this IP address to your trusted list.
   
4. DHCP requests from all managed host IPMI networks have been forwarded to the NICo service running at IP address `NICo_DHCP_EXTERNAL`.

5. You have the following information for all hosts that need to be ingested:

    - The MAC address of the host BMC
    - The chassis serial number 
    - The host BMC username (typically this is the factory default username)
    - The host BMC password (typically this is the factory default password)

## Get client key and certificate needed for nico-admin-cli
These can be generated from site vault. Follow these steps to generate them.NICO_LB_IP
### Prerequisites

1. Check `additional_issuer_cns` (one-time per cluster)
```
kubectl  get configmap -n nico-system nico-api-config-files -o yaml |  grep -i "additional_issuer_cns"
```
Expected: `additional_issuer_cns = ["site-root"]`

If it's empty, edit the configmap and set it, then restart:

```bash
kubectl -n nico-system edit configmap nico-api-config-files
# under [auth.trust]: additional_issuer_cns = ["site-root"]

kubectl rollout restart deployment/nico-api -n nico-system
```

2. Get the CLI binary - You can skip this step you already have nico-admin-cli binary.
```bash
POD=$(kubectl -n nico-system get pods -l app.kubernetes.io/name=nico-api -o jsonpath='{.items[0].metadata.name}')
kubectl -n nico-system cp   "${POD}:/opt/carbide/nico-admin-cli"   /usr/local/bin/nico-admin-cli
chmod +x /usr/local/bin/nico-admin-cli
# verify that it is working 
nico-admin-cli
```

3. Issue a client cert from Vault
```bash
VAULT_TOKEN=$(kubectl -n vault get secret vaultroottoken -o jsonpath='{.data.token}' | base64 -d)
kubectl -n vault exec vault-0 -- env VAULT_SKIP_VERIFY=true VAULT_TOKEN="$VAULT_TOKEN" \
  vault write -format=json nicoca/issue/nico-cluster \
  common_name="<FQDN for nico-api-endpoint>" \
  ttl=720h > /tmp/issued.json
```

Replace `<FQDN for nico-api-endpoint>` appropriately which usually is `api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>`

4. Extract PEM files
```bash
cat /tmp/issued.json | jq -r '.data.private_key' > /path/to/client.key
cat /tmp/issued.json | jq -r '.data.certificate' > /path/to/client.crt
cat /tmp/issued.json | jq -r '.data.issuing_ca' >  /path/to/ca.crt
```

You can run admin cli commands as
```bash
nico-admin-cli https://api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME> --forge-root-ca-path /path/to/ca.crt --client-cert-path /path/to/client.crt  --client-key-path /path/to/client.key <command> ...
```
Alternatively to shorten the command line you can create a file named `carbide_api_cli.json` in folder `$HOME/.config` and add the following content:
```json
{
  "carbide_api_url": "https://api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>:443",
  "root_ca_path": "/path/to/ca.crt",
  "client_cert_path": "/path/to/client.crt",
  "client_key_path": "/path/to/client.key"
}

```
5. Add `/etc/hosts` entry

If you have trouble resolving `api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>` you have to map it to the LoadBalancer IP:

```bash
NICO_LB_IP=$(kubectl -n nico-system get svc nico-api-external \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

grep -q "api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>" /etc/hosts || \
  echo "$NICO_LB_IP api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>" | sudo tee -a /etc/hosts
```

## Update Site 

NICo requires knowledge of the current and desired BMC and UEFI credentials for hosts and DPUs. NICo will reset current crendtials to the desired credentials on the BMC and UEFI when ingesting a host. You can use these credentials when accessing the host or DPU BMC yourself, and NICo will use these credentials for its automated processes.

The required credentials include the following:

- Host BMC Credential
- DPU BMC Credential
- Host UEFI password
- DPU UEFI password

> **Note**:
> The following commands use the `<api-url>` placeholder, which is typically the following:

```bash
https://api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME> --nico-root-ca-path <NICO_ROOT_CA_PATH> --client-cert-path <CLIENT_CERT_PATH>  --client-key-path <CLIENT_KEY_PATH>
```

### Update Host and DPU BMC Password

Run this command to update the desired Host and DPU BMC password:

```bash
nico-admin-cli -c <api-url> credential add-bmc --kind=site-wide-root --password='x'
```

### Update Host UEFI Password

Run this command to generate the desired host UEFI password:

```bash
nico-admin-cli -c <api-url> host generate-host-uefi-password
```


Run this command to update host uefi password:

```bash
nico-admin-cli -c <api-url> credential add-uefi --kind=host --password='<password-gemerated-in-previous-step>'
```

Run this command to update DPU uefi password:
```bash
nico-admin-cli -c <api-url> credential add-uefi --kind=dpu --password='x'
```

## Add Expected Machines Table

NICo needs to know the factory default credentials for each BMC, which is expressed as a JSON table of "Expected Machines".  The serial number is used to verify the BMC MAC matches the actual serial number of the chassis.

Prepare an `expected_machines.json` file as follows:

```json
{
  "expected_machines": [
    {
      "bmc_mac_address": "C4:5A:B1:C8:38:0D",
      "bmc_username": "root",
      "bmc_password": "default-password1",
      "chassis_serial_number": "SERIAL-1"
    },
    {
      "bmc_mac_address": "C4:5A:FF:FF:FF:FF",
      "bmc_username": "root",
      "bmc_password": "default-password2",
      "chassis_serial_number": "SERIAL-2"
    }
  ]
}
```

Only servers listed in this table will be ingested, so you must include all servers in this file.

### Optional Per-Host Fields

Each entry supports additional optional fields:

- **`host_lifecycle_profile`** (object): Per-host profile for settings that affect
  state-machine progression. Future per-host knobs should be added here.
  - **`disable_lockdown`** (bool, default `false`): When `true`, the state machine
    does not lockdown the host during lifecycle management. This is useful for automation
    workflows that need lockdown persistently disabled.

  ```json
  {
    "bmc_mac_address": "C4:5A:B1:C8:38:0D",
    "bmc_username": "root",
    "bmc_password": "default-password1",
    "chassis_serial_number": "SERIAL-1",
    "host_lifecycle_profile": {
      "disable_lockdown": true
    }
  }
  ```

- **`dpf_enabled`** (bool): Enable/disable DPF for this host.
- **`dpu_mode`** (`"dpu_mode"` | `"nic_mode"` | `"no_dpu"`): Per-host DPU operating mode.
- **`bmc_retain_credentials`** (bool): Skip BMC password rotation.
- **`default_pause_ingestion_and_poweron`** (bool): Pause ingestion and power-on for this host.
- **`bmc_ip_address`** (string): Static BMC IP (pre-allocates a machine interface).

When the file is ready, upload it to the site with the following command:

```bash
nico-admin-cli -c <api-url> em replace-all --filename expected_machines.json
```

## Approve all Machines for Ingestion

NICo uses Measured Boot using the on-host Trusted Platform Module (TPM) v2.0 to enforce cryptographic identity of the host hardware and firmware.
The following command configures NICo to approve all pending machines based on PCR Registers 0, 3, 5, and 6.

```bash
nico-admin-cli -c <api-url> att mb site trusted-machine approve \* persist --pcr-registers="0,3,5,6"
```

## What Happens After Approval: Ingestion to Ready

Once machines are approved, NICo's Site Explorer begins automatically ingesting them. No further operator action is required under normal circumstances.

The high-level flow is:

1. **DHCP discovery**: the host BMC sends a DHCP request; NICo assigns an IP and Site Explorer probes the BMC over Redfish to collect a full inventory. Site Explorer authenticates using the factory default credentials from the expected machines table, then rotates the BMC password to the site-wide credential. See [Redfish Workflow](../architecture/redfish_workflow.md) for details.
2. **Preingestion**: before pairing, NICo runs a preingestion state machine against each discovered BMC endpoint (both host and DPU). It checks that the BMC clock is within an acceptable drift of the site time, resetting the BMC if not. For host endpoints, firmware components are upgraded if they are below the minimum version required for ingestion.
3. **DPU-host pairing**: Site Explorer correlates host and DPU serial numbers to form matched pairs. Once all DPUs are validated and matched, the `ManagedHost` object is created and the state machine starts.
4. **`DpuDiscoveringState` / `DPUInit`**: NICo configures Secure Boot on the DPU, installs the DPU OS (BFB image), and power-cycles the host to apply the new DPU configuration.
5. **`HostInit`**: NICo configures BIOS, sets the host boot order, optionally collects TPM attestation measurements, waits for hardware discovery via the `scout` agent, and applies UEFI lockdown. When the `scout` agent reports back, NICo replaces the temporary predicted host ID (prefix `fm100p`) with a stable host ID (prefix `fm100h`) derived from the host's own DMI serial data or TPM certificate.
6. **`BomValidating` / `Validation`**: NICo validates the discovered hardware against the expected SKU. If hardware validation is enabled, the host is rebooted and tested before proceeding.
7. **`Ready`**: the host transitions through `HostInit/Discovered` and enters the available pool, ready for an instance to be assigned to it.

For the full DPU lifecycle — OS installation, firmware upgrades, health monitoring, and reprovisioning — see [DPU Lifecycle Management](../dpu-management/dpu-lifecycle-management.md). For the complete state transitions, including substates, retry logic, and reprovision paths, see the [Managed Host State Diagrams](../architecture/state_machines/managedhost.md).

---

## Troubleshooting: Host and DPU Ingestion Issues

When a machine is not being created or is stuck in a pre-`Ready` state, `nico-api` logs are the primary investigation tool. Filtering logs by the host BMC IP or DPU BMC IP is often the fastest way to understand where ingestion or pairing is failing.

You can check the current detailed state of any managed host using:

```bash
nico-admin-cli -c <api-url> managed-host show --all
nico-admin-cli -c <api-url> managed-host show <machine-id>
```

For a full guide on diagnosing stuck objects, including how to use the NICo Grafana dashboard and how to read state handler error logs, see [Stuck Objects Runbook](../playbooks/stuck_objects/stuck_objects.md).

### Endpoint Exploration Errors

Before pairing can occur, Site Explorer must successfully explore each BMC endpoint. Exploration failures are logged and surfaced in `nico-api` logs and the NICo Grafana dashboard. Common error types:

| Error type | Likely cause |
|---|---|
| `ConnectionTimeout` | BMC unreachable on the OOB network; check cabling and DHCP routing |
| `ConnectionRefused` | No Redfish API exposed at the target IP; the DPU admin IP is often mistakenly probed here |
| `Unauthorized` / `AvoidLockout` | BMC credentials do not match the expected machines table or site vault; see [Adding New Machines: BMC Password Requirements](../playbooks/stuck_objects/adding_new_machines.md) |
| `MissingCredentials` | Credentials not yet available in vault; check that site-wide BMC credentials are configured |
| `UnsupportedVendor` | BMC vendor is not supported by this version of NICo |
| `RedfishError` | Unexpected Redfish response; check BMC firmware version and `nico-api` logs for the full response body |
| `InvalidDpuRedfishBiosResponse` | DPU BIOS endpoint returned an unexpected response; the DPU may need a fresh OS install |

For a complete reference of all Redfish endpoints and required response fields, see [Redfish Endpoints Reference](../architecture/redfish/endpoints_reference.md).

### Common Blockers During Host + DPU Pairing

The following are the conditions in which Site Explorer cannot complete pairing and logs a `host_dpu_pairing_blockers_count` metric. Each requires operator investigation.

| Metric label | Description | Action |
|---|---|---|
| `dpu_nic_mode_unknown` | DPU mode cannot be determined; DPU BMC firmware is likely too old. | Install a fresh DPU OS (which also upgrades firmware); see [Installing a Fresh DPU OS](#dpu-related-issues-installing-a-fresh-dpu-os) below |
| `dpu_pf0_mac_missing` | DPU is in DPU mode but its pf0 MAC address is not retrievable. | Install a fresh DPU OS; see [Installing a Fresh DPU OS](#dpu-related-issues-installing-a-fresh-dpu-os) below |
| `manual_power_cycle_required` | DPU mode was changed but the host vendor does not support automated power cycling. | Manually power-cycle the host at the data center level |
| `host_system_report_missing` | Host BMC Redfish returned no valid system report; likely a BMC firmware issue or transient error. | Check `nico-api` logs for the host BMC IP |
| `no_dpu_reported_by_host` | Host BMC reports no BlueField PCIe devices. | Check DPU seating and host BMC firmware version |
| `boot_interface_mac_mismatch` | Host boot MAC does not match the pf0 MAC of any discovered DPU. | Check exploration reports and `nico-api` logs for both the host and DPU BMC IPs |
| `viking_cpld_version_issue` | NVIDIA Viking (DGX): `CPLDMB_0` firmware below minimum required version (`0.2.1.9`). | Contact the data center team for a full DC power cycle |

### DPU-Related Issues: Installing a Fresh DPU OS

For DPU pairing failures, including `dpu_pf0_mac_missing` and cases where the DPU is in an unknown or corrupt state, a common fix is to install a vanilla pre-ingestion BFB image via rshim to return the DPU to a clean state. This runs as part of the preingestion state machine:

```bash
nico-admin-cli -c <api-url> site-explorer copy-bfb-to-dpu-rshim \
  --host-bmc-ip <host-bmc-ip> \
  <dpu-bmc-ip>
```

This command copies the NICo BFB image directly to the DPU via rshim (SSH to the DPU BMC) and triggers a DPU reboot to complete the installation. After the BFB is installed, NICo power-cycles the host automatically to apply the new DPU image.

> **Note:** The `--host-bmc-ip` flag is required. NICo uses it to power-cycle the host after the BFB copy completes. Use `--pre-copy-powercycle` if the host needs to release rshim control to the DPU BMC before the copy can start.

For additional DPU-specific troubleshooting including Secure Boot configuration, BMC password resets, and firmware version checks, see [Adding New Machines to an Existing Site](../playbooks/stuck_objects/adding_new_machines.md).

---

## Managing the Expected Machines Table

The expected machines table in the nico-api database holds the following fields per host:
- Chassis Serial Number
- BMC MAC Address
- BMC manufacturer's set login
- BMC manufacturer's set password
- DPU chassis serial number (only needed for DGX-H100 or other machines where the NetworkAdapter serial number is not available in the host Redfish)

### Individual operations

Use `nico-admin-cli` to operate on individual entries:

```bash
nico-admin-cli -c <api-url> em update ...
nico-admin-cli -c <api-url> em add ...
nico-admin-cli -c <api-url> em delete ...
```

### Bulk operations

Replace all entries from a JSON file:

```bash
nico-admin-cli -c <api-url> em replace-all --filename expected_machines.json
```

Erase all entries:

```bash
nico-admin-cli -c <api-url> em erase
```

### Export

Export the current table as JSON:

```bash
nico-admin-cli -c <api-url> -f json em show
```