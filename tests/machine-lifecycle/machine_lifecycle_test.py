import io
import os
import subprocess
import sys
import time

import paramiko
import requests
import urllib3

import admin_cli
import network
import ngc
import config
import utils
from vault import ForgeVaultClient

urllib3.disable_warnings()

# Validate config variables
site_under_test = os.environ.get("SITE_UNDER_TEST")  # e.g. "reno-dev4"
if site_under_test is None:
    print("ERROR: $SITE_UNDER_TEST environment variable must be provided. \nExiting...", file=sys.stderr)
    sys.exit(1)
short_site_name = site_under_test.split("-")[1]

machine_under_test = os.environ.get("MACHINE_UNDER_TEST")  # i.e. a machine id
if machine_under_test is None:
    print("ERROR: $MACHINE_UNDER_TEST environment variable must be provided. \nExiting...", file=sys.stderr)
    sys.exit(1)

expected_number_of_dpus = int(os.environ.get("DPU_COUNT", "1"))  # TODO: support an arbitrary number of DPUs
if expected_number_of_dpus not in [1, 2]:
    print("ERROR: $DPU_COUNT environment variable must be set to 1 or 2. \nExiting...", file=sys.stderr)
    sys.exit(1)

factory_reset = os.environ.get("FACTORY_RESET", "false").lower()
if factory_reset not in ["true", "false"]:
    print(
        "ERROR: Invalid value provided for $FACTORY_RESET environment variable. Should be 'true' or 'false'. \nExiting...",
        file=sys.stderr,
    )
    sys.exit(1)

dpu_fw_downgrade = os.environ.get("FW_DOWNGRADE", "false").lower()
if dpu_fw_downgrade not in ["true", "false"]:
    print(
        "ERROR: Invalid value provided for $FW_DOWNGRADE environment variable. Should be 'true' or 'false'. \nExiting...",
        file=sys.stderr,
    )
    sys.exit(1)

if dpu_fw_downgrade == "true":
    fw_downgrade_version = os.environ.get("FW_DOWNGRADE_VERSION")
    if fw_downgrade_version is None:
        print(
        "ERROR: $FW_DOWNGRADE_VERSION environment variable must be provided when $FW_DOWNGRADE is set to 'true'. \nExiting...",
        file=sys.stderr,
        )
        sys.exit(1)

    supported_fw_versions = {
        "2.0.0": config.HBN_2_0_0,
    }
    if fw_downgrade_version not in supported_fw_versions:
        print("ERROR: $FW_DOWNGRADE_VERSION currently only supports '2.0.0' (HBN). \nExiting...", file=sys.stderr)
        sys.exit(1)
    
    # Get firmware versions and URLs from config
    selected_fw = supported_fw_versions[fw_downgrade_version]
    BFB_VERSION = selected_fw["BFB_VERSION"]
    NIC_VERSION = selected_fw["NIC_VERSION"]
    BMC_VERSION = selected_fw["BMC_VERSION"]
    CEC_VERSION = selected_fw["CEC_VERSION"]
    BFB_URL = selected_fw["BFB_URL"]
    NIC_FW_URL = selected_fw["NIC_FW_URL"]
    BMC_FW_URL = selected_fw["BMC_FW_URL"]
    CEC_FW_URL = selected_fw["CEC_FW_URL"]

# Set environment variable CARBIDE_API_URL for forge-admin-cli instead of using --carbide-api
os.environ["CARBIDE_API_URL"] = f"https://api-{short_site_name}.frg.nvidia.com"

sites = [
    ngc.Site("pdx-demo1", "prod"),
    ngc.Site("pdx-dev3", "stg"),
    ngc.Site("reno-dev4", "stg"),
    ngc.Site("pdx-qa2", "qa"),
]

# Find out if the site under test is in production or staging
try:
    site = [_site for _site in sites if _site.name == site_under_test][0]
except IndexError:
    print(f"ERROR: Site {site_under_test} unknown.\nExiting...", file=sys.stderr)
    sys.exit(1)

# Get the appropriate NGC CLI API key out of corp vault
with ForgeVaultClient(path="forge/tokens") as vault_client:
    ngc_api_key = vault_client.get_ngc_api_key(site.environment)

# Get BMC credentials out of corp vault
with ForgeVaultClient(path=site_under_test) as vault_client:
    dpu_bmc_username, dpu_bmc_password = vault_client.get_dpu_bmc_credentials()
    host_bmc_password = vault_client.get_host_bmc_password()

# Get SSH key out of corp vault (vault kv get -mount=secrets forge/machine-lifecycle-test)
with ForgeVaultClient(path="forge/machine-lifecycle-test") as vault_client:
    private_key: str = vault_client.get_ssh_private_key()
with io.StringIO(initial_value=private_key) as ssh_private_key_file:
    ssh_private_key = paramiko.ed25519key.Ed25519Key.from_private_key(ssh_private_key_file)

# Set up NGC CLI environment
ngc_environment = ngc.ENVS[site.environment]
os.environ["NGC_CLI_API_URL"] = ngc_environment.api_url
os.environ["NGC_CLI_API_KEY"] = ngc_api_key
os.environ["NGC_CLI_ORG"] = ngc_environment.tenant_org_name
os.environ["NGC_CLI_DEBUG_LOG"] = "ngc_cli_debug.log"

# Collect machine info
machine = admin_cli.get_machine_from_mh_show(machine_under_test)
machine_vendor = admin_cli.get_machine_vendor(machine_under_test)
if "Lenovo" not in machine_vendor and "Dell" not in machine_vendor:
    print(f"ERROR: {machine_vendor=} is not valid. Expected 'Lenovo' or 'Dell'. \nExiting...", file=sys.stderr)
    sys.exit(1)
print(f"Machine vendor is {machine_vendor}")

if "Dell" in machine_vendor and factory_reset == "true":
    print(
        "ERROR: FACTORY_RESET test option is not yet supported for Dell machines."
        "Set that option to false to test this machine. \nExiting...",
        file=sys.stderr
    )
    sys.exit(1)

host_bmc_username = "USERID" if "Lenovo" in machine_vendor else "root"
host_bmc_ip = machine["host_bmc_ip"]

# Create a dictionary of DPU IDs to their BMC and OOB IPs
dpu_ids: list[str] = []
dpu_bmc_ips: list[str] = []
dpu_info_map: dict[str, dict[str, str]] = {}

for dpu in machine["dpus"]:
    dpu_id = dpu.get("machine_id")
    bmc_ip = dpu.get("bmc_ip")
    oob_ip = dpu.get("oob_ip")
    if dpu_id and bmc_ip and oob_ip:
        dpu_ids.append(dpu_id)
        dpu_bmc_ips.append(bmc_ip)
        dpu_info_map[dpu_id] = {
            "bmc_ip": bmc_ip,
            "oob_ip": oob_ip
        }
    else:
        print(f"ERROR: Missing data for DPU {dpu_id}. \nExiting...", file=sys.stderr)
        sys.exit(1)

# Confirm we found the expected number of DPUs
if len(dpu_info_map) != expected_number_of_dpus:
    print(f"ERROR: Found {len(dpu_info_map)} DPU(s) but expected {expected_number_of_dpus}. \nExiting...",
        file=sys.stderr,
    )
    sys.exit(1)
print(f"DPUs in this machine: {dpu_info_map}")

dpu_model = admin_cli.get_dpu_model(dpu_ids[0])  # Multi-DPUs can be assumed to be of same model (i.e. BF2 or BF3)
if dpu_model.startswith("BlueField SoC") and dpu_fw_downgrade == "true":
    print("ERROR: FW_DOWNGRADE option is not supported for BlueField-2 DPUs. \nExiting...", file=sys.stderr)
    sys.exit(1)

# After force-delete, we'll use the (first) DPU to track state until the host is fully ingested
machine_under_test_dpu = dpu_ids[0]
machine_under_test_predicted_host = machine_under_test_dpu[0:5] + "p" + machine_under_test_dpu[6:]

# Check the initial state is good before we get started
print(f"Checking managed host {machine_under_test} is Ready")
if not admin_cli.check_machine_ready(machine_under_test):
    print("ERROR: Machine is not Ready!\nExiting...", file=sys.stderr)
    sys.exit(1)
print(f"Checking machine {machine_under_test} is not in maintenance mode")
if not admin_cli.check_machine_not_in_maintenance(machine_under_test):
    print("ERROR: Machine is in maintenance mode!\nExiting...", file=sys.stderr)
    sys.exit(1)
print(f"Checking machine {machine_under_test} is not receiving a DPU FW update")
if not admin_cli.check_machine_not_updating(machine_under_test):
    print("ERROR: Machine is receiving a DPU FW update!\nExiting...", file=sys.stderr)
    sys.exit(1)

# Prevent state machine from attempting to reboot the machine
print("Setting health-alert on machine to prevent state machine attempting to reboot it")
try:
    admin_cli.disable_state_machine_intervention(machine_under_test)
except subprocess.CalledProcessError:
    print("Setting health-alert pre-downgrade failed.", file=sys.stderr)
    sys.exit(1)


# Optional DPU firmware downgrade step
if dpu_fw_downgrade == "true":
    print("\n*** Starting DPU firmware downgrade ***")

    bmc_fw_path = os.path.join(os.getcwd(), BMC_FW_URL.split("/")[-1])
    cec_fw_path = os.path.join(os.getcwd(), CEC_FW_URL.split("/")[-1])
    bfb_path = os.path.join(os.getcwd(), BFB_URL.split("/")[-1])

    # Download BMC firmware & BFB if necessary
    if not os.path.isfile(bmc_fw_path):
        try:
            utils.download_firmware_file(BMC_FW_URL)
        except Exception as e:
            print(f"ERROR: BMC firmware failed to download: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)
    if not os.path.isfile(cec_fw_path):
        try:
            utils.download_firmware_file(CEC_FW_URL)
        except Exception as e:
            print(f"ERROR: BMC CEC firmware failed to download: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)
    if not os.path.isfile(bfb_path):
        try:
            utils.download_firmware_file(BFB_URL)
        except Exception as e:
            print(f"ERROR: BFB failed to download: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)

    # Put machine into maintenance mode to prevent Forge trying to upgrade it
    print("Putting machine into maintenance mode before firmware downgrade")
    try:
        admin_cli.put_machine_into_maintenance_mode(machine_under_test)
    except subprocess.CalledProcessError:
        print("Setting maintenance mode pre-downgrade failed.", file=sys.stderr)
        sys.exit(1)

    # Apply specified BMC firmware and wait for redfish task completion
    for dpu_id in dpu_ids:
        print(f"Downgrading BMC firmware of {dpu_id}")
        try:
            utils.apply_dpu_bmc_firmware(bmc_fw_path, dpu_info_map[dpu_id]["bmc_ip"], dpu_bmc_username, dpu_bmc_password)
        except Exception as e:
            print(f"ERROR: BMC firmware downgrade failed on {dpu_id}: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)

    # Apply specified BMC CEC firmware and wait for redfish task completion
    for dpu_id in dpu_ids:
        print(f"Downgrading CEC firmware of {dpu_id}")
        try:
            utils.apply_dpu_bmc_firmware(cec_fw_path, dpu_info_map[dpu_id]["bmc_ip"], dpu_bmc_username, dpu_bmc_password)
        except Exception as e:
            print(f"ERROR: CEC firmware downgrade failed on {dpu_id}: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)

    # Power-cycle host
    print(f"Power-cycling host {host_bmc_ip} after BMC & CEC downgrades")
    try:
        utils.power_cycle_host(machine_vendor, host_bmc_ip, host_bmc_username, host_bmc_password)
        time.sleep(10)
        [network.wait_for_host_port(dpu_info_map[dpu_id]["oob_ip"], 22, max_retries=20) for dpu_id in dpu_ids]
        [network.wait_for_redfish_endpoint(hostname=dpu_info_map[dpu_id]["bmc_ip"]) for dpu_id in dpu_ids]
    except Exception as e:
        print(f"ERROR: Failed to power-cycle host {host_bmc_ip}: {e}\nExiting...", file=sys.stderr)
        sys.exit(1)

    # Verify downgraded BMC & CEC versions
    for dpu_id in dpu_ids:
        try:
            bmc_version = utils.get_reported_bmc_version(dpu_info_map[dpu_id]["bmc_ip"], dpu_bmc_username, dpu_bmc_password)
            if BMC_VERSION not in bmc_version:
                print(
                    f"ERROR: DPU {dpu_id} reports BMC version {bmc_version}, expected {BMC_VERSION}. \nExiting...",
                    file=sys.stderr
                )
                sys.exit(1)
            print(f"Successfully downgraded BMC to {BMC_VERSION} on {dpu_id}")

            cec_version = utils.get_reported_cec_version(dpu_info_map[dpu_id]["bmc_ip"], dpu_bmc_username, dpu_bmc_password)
            if CEC_VERSION not in cec_version:
                print(
                    f"ERROR: DPU {dpu_id} reports CEC version {cec_version}, expected {CEC_VERSION}. \nExiting...",
                    file=sys.stderr
                )
                sys.exit(1)
            print(f"Successfully downgraded CEC to {CEC_VERSION} on {dpu_id}")
        except Exception as e:
            print(f"ERROR: Failed to confirm BMC & CEC versions on {dpu_id}: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)

    # Ensure rshim is enabled on DPU(s)
    for dpu_id in dpu_ids:
        try:
            utils.enable_rshim_on_dpu(dpu_info_map[dpu_id]["bmc_ip"], dpu_bmc_username, dpu_bmc_password)
            time.sleep(10)
        except Exception as e:
            print(f"ERROR: Failed to enable rshim on DPU {dpu_id}: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)

    # Copy BFB file to DPU(s)
    for dpu_id in dpu_ids:
        print(f"Downgrading BFB on {dpu_id}")
        try:
            utils.copy_bfb_to_dpu(bfb_path, dpu_info_map[dpu_id]["bmc_ip"], dpu_bmc_username, dpu_bmc_password)
        except Exception as e:
            print(f"ERROR: Failed to copy BFB to DPU {dpu_id}: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)

    print("Sleeping for 5 minutes for BFB install to complete...")
    time.sleep(60 * 5)

    # Downgrade NIC firmware on DPU(s)
    for dpu_id in dpu_ids:
        try:
            utils.apply_nic_firmware(
                NIC_FW_URL,
                dpu_info_map[dpu_id]["bmc_ip"],
                dpu_bmc_username,
                dpu_bmc_password
            )
        except Exception as e:
            print(f"ERROR: Failed to downgrade NIC firmware on DPU {dpu_id}: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)

    # Power-cycle host
    print(f"Power-cycling host {host_bmc_ip} after BFB & NIC downgrade")
    try:
        utils.power_cycle_host(machine_vendor, host_bmc_ip, host_bmc_username, host_bmc_password)
        # admin_cli.restart_machine(machine_under_test)
        time.sleep(10)
        [network.wait_for_host_port(dpu_info_map[dpu_id]["oob_ip"], 22, max_retries=20) for dpu_id in dpu_ids]
        [network.wait_for_redfish_endpoint(hostname=dpu_info_map[dpu_id]["bmc_ip"]) for dpu_id in dpu_ids]
        time.sleep(20)  # Workaround for brief 400 error
    except Exception as e:
        print(f"ERROR: Failed to power-cycle host {host_bmc_ip}: {e}\nExiting...", file=sys.stderr,)
        sys.exit(1)

    # Verify downgraded BFB & NIC versions
    for dpu_id in dpu_ids:
        try:
            bfb_version = utils.get_reported_bfb_version(
                dpu_info_map[dpu_id]["bmc_ip"],
                dpu_bmc_username,
                dpu_bmc_password,
            )
            if BFB_VERSION not in bfb_version:
                print(
                    f"ERROR: DPU {dpu_id} reports BFB version {bfb_version}, expected {BFB_VERSION}\nExiting...",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(f"Successfully downgraded BFB to {BFB_VERSION} on {dpu_id}")

            nic_version = utils.get_reported_nic_version(
                dpu_info_map[dpu_id]["bmc_ip"],
                dpu_bmc_username,
                dpu_bmc_password,
            )
            if NIC_VERSION not in nic_version:
                print(
                    f"ERROR: DPU {dpu_id} reports NIC version {nic_version}, expected {NIC_VERSION}\nExiting...",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(f"Successfully downgraded NIC to {NIC_VERSION} on {dpu_id}")
        except Exception as e:
            print(f"ERROR: Failed to confirm BFB & NIC versions on {dpu_id}: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)

    # Remove firmware files from test runner machine
    files_to_remove = [bmc_fw_path, cec_fw_path, bfb_path]
    for file in files_to_remove:
        try:
            os.remove(file)
        except FileNotFoundError as e:
            print(f"File not found for removal: {e}")
        except Exception as e:
            print(f"ERROR: Failed to remove firmware file: {e}\nExiting...", file=sys.stderr)
            sys.exit(1)


# Optional factory-reset step (soon to be non-optional if the DPU firmware was just downgraded)
if factory_reset == "true":
    print("\n*** Starting factory-reset ***")

    # Factory-reset DPU(s)
    i = 1
    for dpu_id in dpu_ids:
        print(f"Resetting BIOS settings on DPU{i}")
        if dpu_fw_downgrade == "true":
            # Different endpoint in redfish v1.9.0
            url = "https://%s/redfish/v1/Systems/Bluefield/Bios/Actions/Bios.ResetBios" % dpu_info_map[dpu_id]["bmc_ip"]
            print(f"Executing redfish request. \nURL: {url}")
            response = requests.post(url, auth=(dpu_bmc_username, dpu_bmc_password), verify=False)
        else:
            url = "https://%s/redfish/v1/Systems/Bluefield/Bios/Settings" % dpu_info_map[dpu_id]["bmc_ip"]
            data = {"Attributes": {"ResetEfiVars": True}}
            print(f"Executing redfish request. \nPayload: {data} \nURL: {url}")
            response = requests.patch(
                url, json=data, auth=(dpu_bmc_username, dpu_bmc_password), verify=False
            )
        if response.status_code != 200:
            print(response.text)
            print(f"ERROR: Failed to reset BIOS settings on DPU{i}. Status code: {response.status_code}. \nExiting...")
            try:
                admin_cli.put_machine_into_maintenance_mode(machine_under_test)
            except subprocess.CalledProcessError:
                print("Setting maintenance mode failed.", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Resetting BIOS settings on DPU{i} was successful.")
            time.sleep(5)
        print(f"Restarting DPU{i} BMC")
        admin_cli.restart_bmc(dpu_id)
        time.sleep(5)
        network.wait_for_redfish_endpoint(hostname=dpu_info_map[dpu_id]["bmc_ip"])
        time.sleep(30)

        print(f"Factory-resetting DPU{i} BMC")
        admin_cli.factory_reset_bmc(dpu_info_map[dpu_id]["bmc_ip"], dpu_bmc_username, dpu_bmc_password)
        time.sleep(5)
        network.wait_for_redfish_endpoint(hostname=dpu_info_map[dpu_id]["bmc_ip"])
        i += 1

    # Factory-reset Host
    print("Resetting BIOS settings on the host")
    url = "https://%s/redfish/v1/Systems/1/Bios/Actions/Bios.ResetBios" % host_bmc_ip
    data = {"ResetType": "default"}
    print(f"Executing redfish request. \nData: {data} \nURL: {url}")
    response = requests.post(
        url, json=data, auth=(host_bmc_username, host_bmc_password), verify=False
    )
    if response.status_code != 202:
        print(response.text)
        print(
            f"ERROR: Failed to reset BIOS settings on the host. Status code: {response.status_code}. \nExiting..."
        )
        try:
            admin_cli.put_machine_into_maintenance_mode(machine_under_test)
        except subprocess.CalledProcessError:
            print("Setting maintenance mode failed.", file=sys.stderr)
        sys.exit(1)
    else:
        task_id = response.json()["Id"]
        attempts = 0
        max_attempts = 30
        print(f"Waiting for async redfish task {task_id} to complete")
        while attempts < max_attempts:
            url = f"https://{host_bmc_ip}/redfish/v1/TaskService/Tasks/{task_id}"
            response = requests.get(url, auth=(host_bmc_username, host_bmc_password), verify=False)
            if response.status_code != 200:
                print(response.text)
                print(
                    f"ERROR: Failed to get redfish task status. Status code: {response.status_code}. \nExiting..."
                )
                try:
                    admin_cli.put_machine_into_maintenance_mode(machine_under_test)
                except subprocess.CalledProcessError:
                    print("Setting maintenance mode failed.", file=sys.stderr)
                sys.exit(1)
            if response.json()["TaskState"] == "Completed":
                print("Redfish task completed.")
                break
            else:
                print("Redfish task not yet completed, state %s" % response.json()["TaskState"])
                attempts += 1
                time.sleep(10)
        else:
            print("ERROR: Redfish task did not complete in 5 minutes. \nExiting...")
            try:
                admin_cli.put_machine_into_maintenance_mode(machine_under_test)
            except subprocess.CalledProcessError:
                print("Setting maintenance mode failed.", file=sys.stderr)
            sys.exit(1)
    print("Removing the BIOS password from the host")
    admin_cli.clear_host_bios_password(machine_under_test)
    print("Restarting the host")
    admin_cli.restart_machine(machine_under_test)
    time.sleep(10)
    network.wait_for_redfish_endpoint(hostname=host_bmc_ip)

    print("Factory-resetting the host BMC")
    admin_cli.factory_reset_bmc(host_bmc_ip, host_bmc_username, host_bmc_password)
    time.sleep(5)
    network.wait_for_redfish_endpoint(hostname=host_bmc_ip)

    # Ensure the machine is still "Ready" after the factory-reset
    print(f"Checking {machine_under_test} is still Ready")
    if not admin_cli.check_machine_ready(machine_under_test):
        print(f"ERROR: Machine {machine_under_test} is no longer Ready! \nExiting...", file=sys.stderr)
        try:
            admin_cli.put_machine_into_maintenance_mode(machine_under_test)
        except subprocess.CalledProcessError:
            print("Setting maintenance mode failed.", file=sys.stderr)
        sys.exit(1)

# Force-delete machine from Forge database
print(f"Force-deleting machine {machine_under_test}")
if factory_reset == "true":
    admin_cli.force_delete_machine(machine_under_test, delete_creds=True)
else:
    admin_cli.force_delete_machine(machine_under_test, delete_creds=False)

# Discovery portion.
# If there is a failure anywhere here attempt to put the machine into maintenance mode
# for investigation (this will prevent future runs affecting the machine).
try:
    # Wait up to 1 hour for HostInitializing
    print(f"Waiting for carbide to report DPU {machine_under_test_dpu} in any 'HostInitializing' state")
    hostinit_timeout = config.WAIT_FOR_HOSTINIT_AFTER_DOWNGRADE if dpu_fw_downgrade == "true" else config.WAIT_FOR_HOSTINIT
    admin_cli.wait_for_machine_hostinitializing(machine_under_test_dpu, timeout=hostinit_timeout)

    # Wait for Ready state
    print(f"Waiting for carbide to report DPU {machine_under_test_dpu} Ready")
    admin_cli.wait_for_machine_ready(machine_under_test_dpu, timeout=config.WAIT_FOR_READY)
except Exception as e:
    print(e.args[0], file=sys.stderr)
    print("Exception while waiting for machine Ready, putting machine into maintenance mode", file=sys.stderr)
    # We have to use managed host ID to do this, not DPU ID, but this may not exist
    # in the database yet depending on where the process got to before it failed.
    # If using that doesn't work, try again with the predicted host id.
    try:
        admin_cli.put_machine_into_maintenance_mode(machine_under_test)
    except subprocess.CalledProcessError as e:
        print(e, file=sys.stderr)
        try:
            print("Setting maintenance mode failed, trying again using predicted host id", file=sys.stderr)
            admin_cli.put_machine_into_maintenance_mode(machine_under_test_predicted_host)
        except Exception as e:
            print(e, file=sys.stderr)
        finally:
            sys.exit(1)
    finally:
        sys.exit(1)

# If we performed a DPU FW downgrade prior to discovery, confirm the DPU FW has now been auto-upgraded by Forge
if dpu_fw_downgrade == "true":
    for dpu_id in dpu_ids:
        try:
            bmc_version = utils.get_reported_bmc_version(
                dpu_info_map[dpu_id]["bmc_ip"],
                dpu_bmc_username,
                dpu_bmc_password
            )
            if config.BMC_VERSION_UP not in bmc_version:
                print(
                    f"ERROR: DPU {dpu_id} reports BMC version {bmc_version}, expected {config.BMC_VERSION_UP}."
                    f"\nExiting...",
                    file=sys.stderr
                )
                sys.exit(1)
            print(f"Forge successfully upgraded BMC to {config.BMC_VERSION_UP} on {dpu_id}")

            cec_version = utils.get_reported_cec_version(
                dpu_info_map[dpu_id]["bmc_ip"],
                dpu_bmc_username,
                dpu_bmc_password
            )
            if config.CEC_VERSION_UP not in cec_version:
                print(
                    f"ERROR: DPU {dpu_id} reports CEC version {cec_version}, expected {config.CEC_VERSION_UP}."
                    f"\nExiting...",
                    file=sys.stderr
                )
                sys.exit(1)
            print(f"Forge successfully upgraded CEC to {config.CEC_VERSION_UP} on {dpu_id}")

            bfb_version = utils.get_reported_bfb_version(
                    dpu_info_map[dpu_id]["bmc_ip"],
                    dpu_bmc_username,
                    dpu_bmc_password,
                )
            if config.BFB_VERSION_UP not in bfb_version:
                print(
                    f"ERROR: DPU {dpu_id} reports BFB version {bfb_version}, expected {config.BFB_VERSION_UP}."
                    f"\nExiting...",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(f"Forge successfully upgraded BFB to {config.BFB_VERSION_UP} on {dpu_id}")

            nic_version = utils.get_reported_nic_version(
                dpu_info_map[dpu_id]["bmc_ip"],
                dpu_bmc_username,
                dpu_bmc_password,
            )
            if config.NIC_VERSION_UP not in nic_version:
                print(
                    f"ERROR: DPU {dpu_id} reports NIC version {nic_version}, expected {config.NIC_VERSION_UP}."
                    f"Exiting...",
                    file=sys.stderr,
                )
                sys.exit(1)
            print(f"Forge successfully upgraded NIC to {config.NIC_VERSION_UP} on {dpu_id}")
        except Exception as e:
            print(
                f"ERROR: Failed to confirm firmware versions on {dpu_id} after re-discovery: {e}\nExiting...",
                file=sys.stderr
            )
            sys.exit(1)

# After the DPU state gets to Ready, allow for the possibility that Forge tries to update the DPU FW.
# Then confirm the managed host and Cloud machine states both show Ready too.
print("Sleeping for 2 minutes to allow Forge to possibly grab the machine for a DPU FW upgrade...")
time.sleep(60 * 2)

print("Waiting for the machine not to be receiving a DPU FW update from Forge...")
admin_cli.wait_for_machine_not_updating(machine_under_test, timeout=60 * 90)

print("Checking that carbide reports the managed host Ready")
admin_cli.check_machine_ready(machine_under_test)

print("Waiting for the Cloud to also report machine Ready")
ngc.wait_for_machine_ready(machine_under_test, site, timeout=60 * 10)

# Get required UUIDs from NGC
site_uuid = ngc.get_site_uuid(site.name)
print(f"{site_uuid=}")
instance_type_name = "machine-lifecycle-test"
if expected_number_of_dpus == 2:
    instance_type_name = "machine-lifecycle-test-dual-dpu"
instance_name = f"machine-lifecycle-test-instance-{expected_number_of_dpus}"
print(f"{instance_type_name=}")
instance_type_uuid = ngc.get_instance_type_uuid(instance_type_name, site_uuid)
print(f"{instance_type_uuid=}")
vpc_uuid = ngc.get_vpc_uuid("machine-lifecycle-test-vpc", site_uuid)
print(f"{vpc_uuid=}")
subnet_uuid = ngc.get_subnet_uuid("machine-lifecycle-test-subnet", vpc_uuid)
print(f"{subnet_uuid=}")
os_uuid = ngc.get_operating_system_uuid("machine-lifecycle-test-os")
print(f"{os_uuid=}")

# We could supply --user-data here to customize the OS with our SSH public key direct from vault,
# but we can revisit this if we need to change anything. We expect it to be static.
print("Creating an instance on the machine")
instance = ngc.create_instance(instance_name, instance_type_uuid, subnet_uuid, os_uuid, vpc_uuid)
instance_uuid = instance["id"]
print(f"Instance {instance_uuid} creation success")

try:
    print("Waiting for carbide to report machine 'Assigned/Ready'")
    admin_cli.wait_for_machine_assigned_ready(machine_under_test, timeout=60 * 10)

    # With 'phone-home' enabled, Forge Cloud will only report the instance 'Ready' once it has booted and reported back
    print("Waiting for Forge Cloud to report instance 'Ready' to the tenant")
    ngc.wait_for_instance_ready(instance_uuid, site, timeout=config.WAIT_FOR_INSTANCE)

    instance_ip_address = ngc.wait_for_instance_ip(instance_uuid, subnet_uuid, timeout=60 * 20)

    print(f"Testing SSH connection to the instance {instance_uuid} at {instance_ip_address}")
    network.wait_for_host_port(instance_ip_address, 22, max_retries=40)
    with paramiko.SSHClient() as ssh_client:
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(
            instance_ip_address,
            pkey=ssh_private_key,
            username="machine-lifecycle-test-user",
        )

        command = "uptime"
        print(f"Executing command: {command} on instance {instance_uuid} at {instance_ip_address}")
        i, o, e = ssh_client.exec_command(command)
        stdout = o.readlines()
        stderr = e.readlines()
        exit_status = o.channel.recv_exit_status()
        print(f"{command!r} stdout: {stdout}")
        print(f"{command!r} stderr: {stderr}")
        if exit_status != 0:
            print(f"{command!r} exited with status {exit_status}", file=sys.stderr)

    # Delete the instance
    print("Deleting the instance")
    ngc.delete_instance(instance_uuid)

    # Wait for the instance to be deleted
    print("Waiting for the instance to be deleted")
    ngc.wait_for_vpc_to_not_contain_instance(site_uuid, vpc_uuid, instance_uuid, timeout=60 * 90)

    print("Waiting for carbide to report the managed host Ready")
    admin_cli.wait_for_machine_ready(machine_under_test, timeout=60 * 90)
except Exception as e:
    print(e.args[0], file=sys.stderr)
    print(
        "Exception while performing instance creation/deletion, putting machine into maintenance mode", file=sys.stderr
    )
    admin_cli.put_machine_into_maintenance_mode(machine_under_test)
    sys.exit(1)

# After the managed host state gets to Ready, allow for the possibility that Forge tries to upgrade the DPU FW.
# Then confirm the managed host state once more and wait for Cloud machine state to be Ready too.
print("Sleeping for 2 minutes to allow Forge to possibly grab the machine for a DPU FW upgrade...")
time.sleep(60 * 2)

print("Waiting for the machine not to be receiving a DPU FW update from Forge...")
admin_cli.wait_for_machine_not_updating(machine_under_test, timeout=60 * 10)

print("Checking again that carbide reports the managed host Ready")
admin_cli.check_machine_ready(machine_under_test)

print("Waiting for Forge Cloud to also report machine Ready to the provider")
ngc.wait_for_machine_ready(machine_under_test, site, timeout=60 * 10)
