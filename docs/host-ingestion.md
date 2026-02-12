# Host Ingestion

Once you have NVIDIA Bare Metal Manager (BMM) up and running, you can begin ingesting managed hosts. 

## Prerequisites

Ensure you have the following prerequisites met before ingesting hosts:

1. You have the `admin-cli` command available: You can compile it from sources or you can use the pre-compiled binary. Another choice is to use a containerized version.

2. You can access the BMM site using the `admin-cli`.

3. The BMM API service is running at IP address `BMM_API_EXTERNAL`. It is recommended that you add this IP address to your trusted list.
   
4. DHCP requests from all managed host IPMI networks have been forwarded to the BMM service running at IP address `BMM_DHCP_EXTERNAL`.

5. You have the following information for all hosts that need to be ingested:

    - The MAC address of the host BMC
    - The chassis serial number 
    - The host BMC username (typically this is the factory default username)
    - The host BMC password (typically this is the factory default password)

## Update Site 

BMM requires knowledge of the desired BMC and UEFI credentials for hosts and DPUs. BMM will set these credentials on the BMC and UEFI when ingesting a host. You can use these credentials when accessing the host or DPU BMC yourself, and BMM will use these credentials for its automated processes.

The required credentials include the following:

- Host BMC Credential
- DPU BMC Credential
- Host UEFI password
- DPU UEFI password

:::{note}
The following commands use the `<api-url>` placeholder, which is typically the following:

```bash
https://api-<ENVIRONMENT_NAME>.<SITE_DOMAIN_NAME>
```

:::

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

### Update DPU UEFI Password

TODO: Need to add this command.

## Add Expected Machines Table

BMM needs to know the factory default credentials for each BMC, which is expressed as a JSON table of "Expected Machines".  The serial number is used to verify the BMC MAC matches the actual serial number of the chassis.

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

When the file is ready, upload it to the site with the following command:

```bash
admin-cli -c <api-url> credential em replace-all --filename expected_machines.json
```

## Approve all Machines for Ingestion

BMM uses Measured Boot using the on-host Trusted Platform Module (TPM) v2.0 to enforce cryptographic identity of the host hardware and firmware.
The following command configures BMM to approve all pending machines based on PCR Registers 0, 3, 5, and 6.

```bash
admin-cli -c <api-url> mb site trusted-machine approve \* persist --pcr-registers="0,3,5,6"
```

