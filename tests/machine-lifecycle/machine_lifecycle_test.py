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
from vault import ForgeVaultClient

urllib3.disable_warnings()


WAIT_FOR_HOSTINIT = 60 * 90
WAIT_FOR_READY = 60 * 120

# Get config variables from environment
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

# Set environment variable CARBIDE_API_URL for forge-admin-cli instead of using --carbide-api
os.environ["CARBIDE_API_URL"] = f"https://api-{short_site_name}.frg.nvidia.com"

sites = [
    ngc.Site("pdx-demo1", "prod"),
    ngc.Site("pdx-dev3", "stg"),
    ngc.Site("reno-dev4", "stg"),
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

# Get DPU BMC credentials out of corp vault
with ForgeVaultClient(path=site_under_test) as vault_client:
    dpu_bmc_username, dpu_bmc_password = vault_client.get_dpu_bmc_credentials()
    host_bmc_username, host_bmc_password = vault_client.get_host_bmc_credentials()

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

# Collect DPU machine ID(s) for later
machine = admin_cli.get_machine(machine_under_test)
host_bmc_ip = machine["host_bmc_ip"]
dpus_under_test: list[str] = []  # list of DPU machine ids (fm100d...)
for dpu in machine["dpus"]:
    dpus_under_test.append(dpu["machine_id"])
print(f"DPUs in this machine: {dpus_under_test}")
# Once we force-delete, we'll have to use a DPU machine ID to look it up until host fully ingested
machine_under_test_dpu = dpus_under_test[0]
machine_under_test_predicted_host = machine_under_test_dpu[0:5] + "p" + machine_under_test_dpu[6:]


# Check the initial state is good before we get started
print(f"Checking managed host {machine_under_test} is Ready")
if not admin_cli.check_machine_ready(machine_under_test):
    print(f"ERROR: Machine {machine_under_test} is not Ready!\nExiting...", file=sys.stderr)
    sys.exit(1)
print(f"Checking machine {machine_under_test} is not in maintenance mode")
if not admin_cli.check_machine_not_in_maintenance(machine_under_test):
    print(f"ERROR: Machine {machine_under_test} is in Maintenance!\nExiting...", file=sys.stderr)
    sys.exit(1)


# Optional factory-reset step
if factory_reset == "true":
    # Get vendor name of the host machine
    machine_vendor = admin_cli.get_machine_vendor(machine_under_test)
    if machine_vendor not in ["Lenovo", "Dell"]:
        print(f"ERROR: {machine_vendor=} is not valid. Expected 'Lenovo' or 'Dell'. \nExiting...", file=sys.stderr)
        sys.exit(1)
    print(f"Machine vendor is {machine_vendor}")

    # Grab DPU BMC IP(s)
    dpu_bmc_ips = [dpu["bmc_ip"] for dpu in machine["dpus"]]
    if len(dpu_bmc_ips) != expected_number_of_dpus:
        print(
            f"ERROR: Found DPU BMC IP(s) {dpu_bmc_ips} but expected DPU_COUNT={expected_number_of_dpus}. \nExiting...",
            file=sys.stderr,
        )
        sys.exit(1)

    # Factory-reset DPU(s)
    i = 1
    for dpu_bmc_ip in dpu_bmc_ips:
        print(f"Resetting BIOS settings on DPU{i}")
        url = "https://%s/redfish/v1/Systems/Bluefield/Bios/Settings" % dpu_bmc_ip
        payload = {"Attributes": {"ResetEfiVars": True}}
        headers = {"Content-Type": "application/json"}
        print(f"Executing redfish request. \nPayload: {payload} \nURL: {url}")
        response = requests.patch(
            url, headers=headers, json=payload, auth=(dpu_bmc_username, dpu_bmc_password), verify=False
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
        admin_cli.restart_bmc(machine_under_test_dpu)
        time.sleep(5)
        network.wait_for_redfish_endpoint(hostname=dpu_bmc_ip)
        time.sleep(30)

        print(f"Factory-resetting DPU{i} BMC")
        admin_cli.factory_reset_bmc(dpu_bmc_ip, dpu_bmc_username, dpu_bmc_password)
        time.sleep(5)
        network.wait_for_redfish_endpoint(hostname=dpu_bmc_ip)
        i += 1

    # Factory-reset Host
    if machine_vendor == "Lenovo":
        print("Resetting BIOS settings on the host")
        url = "https://%s/redfish/v1/Systems/1/Bios/Actions/Bios.ResetBios" % host_bmc_ip
        data = '{"ResetType": "default"}'
        headers = {"Content-Type": "application/json"}
        print(f"Executing redfish request. \nData: {data} \nURL: {url}")
        response = requests.post(
            url, headers=headers, data=data, auth=(host_bmc_username, host_bmc_password), verify=False
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
                headers = {"Content-Type": "application/json"}
                response = requests.get(url, headers=headers, auth=(host_bmc_username, host_bmc_password), verify=False)
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

    elif machine_vendor == "Dell":
        # TODO: support Dell factory-reset
        print("Dell machines not yet supported for factory-reset. Skipping...")

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
    admin_cli.wait_for_machine_hostinitializing(machine_under_test_dpu, timeout=WAIT_FOR_HOSTINIT)

    # Wait for Ready state
    print(f"Waiting for carbide to report DPU {machine_under_test_dpu} Ready")
    admin_cli.wait_for_machine_ready(machine_under_test_dpu, timeout=WAIT_FOR_READY)
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


# After the DPU state gets to Ready, allow for the possibility that carbide tries to upgrade the DPU FW.
# Then confirm the managed host and Cloud machine states both show Ready too.
print("Sleeping for 2 minutes to allow carbide to possibly grab the machine for a DPU FW upgrade...")
time.sleep(60 * 2)

print("Waiting for the machine not to be in maintenance mode (in case carbide is upgrading the DPU FW)")
admin_cli.wait_for_machine_not_in_maintenance(machine_under_test, timeout=60 * 90)

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
subnet_uuid = ngc.get_subnet_uuid("machine-lifecycle-test-subnet")
print(f"{subnet_uuid=}")
os_uuid = ngc.get_operating_system_uuid("machine-lifecycle-test-os")
print(f"{os_uuid=}")
vpc_uuid = ngc.get_virtual_private_cloud_uuid("machine-lifecycle-test-vpc")
print(f"{vpc_uuid=}")


# We could supply --user-data here to customize the OS with our SSH public key direct from vault,
# but we can revisit this if we need to change anything. We expect it to be static.
print("Creating an instance on the machine")
instance = ngc.create_instance(instance_name, instance_type_uuid, subnet_uuid, os_uuid, vpc_uuid)
instance_uuid = instance["id"]
print(f"Instance {instance_uuid} creation success")

try:
    print(f"Waiting for {machine_under_test} to report state 'Assigned/Ready'")
    admin_cli.wait_for_machine_assigned_ready(machine_under_test, timeout=60 * 10)

    print("Sleeping for 30 minutes for instance installation...")
    # The problem is that here, there will be an instance reboot, and we want to wait until
    # after that before attempting to test out SSH connection.
    time.sleep(60 * 30)

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


# After the managed host state gets to Ready, allow for the possibility that carbide tries to upgrade the DPU FW.
# Then confirm the managed host state once more and wait for Cloud machine state to be Ready too.
print("Sleeping for 2 minutes to allow carbide to possibly grab the machine for a DPU FW upgrade...")
time.sleep(60 * 2)

print("Waiting for the machine not to be in maintenance mode (in case carbide is upgrading the DPU FW)")
admin_cli.wait_for_machine_not_in_maintenance(machine_under_test, timeout=60 * 90)

print("Checking again that carbide reports the managed host Ready")
admin_cli.check_machine_ready(machine_under_test)

print("Waiting for the Cloud to also report machine Ready")
ngc.wait_for_machine_ready(machine_under_test, site, timeout=60 * 10)
