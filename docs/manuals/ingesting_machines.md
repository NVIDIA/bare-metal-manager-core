# Ingesting Hosts

Once you have NVIDIA Infra Controller (NICo) up and running, you can begin ingesting machines.

## Prerequisites

Ensure you have the following prerequisites met before ingesting machines:

1. You have the `admin-cli` command available: You can compile it from sources or you can use the pre-compiled binary. Another choice is to use a containerized version.

2. You can access the NICo site using the `admin-cli`.

3. The NICo API service is running at IP address `NICo_API_EXTERNAL`. It is recommended that you add this IP address to your trusted list.
   
4. DHCP requests from all managed host IPMI networks have been forwarded to the NICo service running at IP address `NICo_DHCP_EXTERNAL`.

5. You have the following information for all hosts that need to be ingested:

    - The MAC address of the host BMC
    - The chassis serial number 
    - The host BMC username (typically this is the factory default username)
    - The host BMC password (typically this is the factory default password)

## Update Site 

NICo requires knowledge of the desired BMC and UEFI credentials for hosts and DPUs. NICo will set these credentials on the BMC and UEFI when ingesting a host. You can use these credentials when accessing the host or DPU BMC yourself, and NICo will use these credentials for its automated processes.

The required credentials include the following:

- Host BMC Credential
- DPU BMC Credential
- Host UEFI password
- DPU UEFI password

> **Note**:
> The following commands use the `<api-url>` placeholder, which is typically the following:

```bash
https://api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>
```

### Update Host and DPU BMC Password

Run this command to update the desired Host and DPU BMC password:

```bash
admin-cli -c <api-url> credential add-bmc --kind=site-wide-root --password='x'
```

### Update Host UEFI Password

Run this command to update the desired host UEFI password:

```bash
admin-cli -c <api-url> host generate-host-uefi-password
```


Run this command to update host uefi password:

```bash
admin-cli -c <api-url> credential add-uefi --kind=host --password='x'
```

{/* TODO: Need to add "update DPU UEFI password" command. */}

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
admin-cli -c <api-url> credential em replace-all --filename expected_machines.json
```

## Approve all Machines for Ingestion

NICo uses Measured Boot using the on-host Trusted Platform Module (TPM) v2.0 to enforce cryptographic identity of the host hardware and firmware.
The following command configures NICo to approve all pending machines based on PCR Registers 0, 3, 5, and 6.

```bash
admin-cli -c <api-url> mb site trusted-machine approve \* persist --pcr-registers="0,3,5,6"
```