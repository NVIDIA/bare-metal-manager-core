import io
import os
import subprocess
import sys
import time

import paramiko

import admin_cli
import network
import ngc
from vault import ForgeVaultClient

site_under_test = os.environ.get("SITE_UNDER_TEST")  # e.g. "pdx-demo1"
if site_under_test is None:
    print("$SITE_UNDER_TEST environment variable must be set", file=sys.stderr)
    sys.exit(1)
short_site_name = site_under_test.split("-")[1]

machine_under_test = os.environ.get("MACHINE_UNDER_TEST")  # i.e. a machine id
if machine_under_test is None:
    print("$MACHINE_UNDER_TEST environment variable must be set", file=sys.stderr)
    sys.exit(1)

# Set environment variable CARBIDE_API_URL instead of using --carbide-api
os.environ["CARBIDE_API_URL"] = f"https://api-{short_site_name}.frg.nvidia.com"

sites = [
    ngc.Site("pdx-demo1", "prod", ngc_name="demo01"),
    ngc.Site("pdx-dev3", "stg"),
    ngc.Site("reno-dev4", "stg"),
]

# Find out if the site under test is in production or staging
try:
    site = [_site for _site in sites if _site.name == site_under_test][0]
except IndexError:
    print(f"Site {site_under_test} unknown", file=sys.stderr)
    sys.exit(1)

# Get the appropriate ngc cli API key out of corp vault
with ForgeVaultClient(path="forge/tokens") as vault_client:
    ngc_api_key = vault_client.get_ngc_api_key(site.environment)

# Set up ngc environment
ngc_environment = ngc.ENVS[site.environment]
os.environ["NGC_CLI_API_URL"] = ngc_environment.api_url
os.environ["NGC_CLI_API_KEY"] = ngc_api_key
os.environ["NGC_CLI_ORG"] = ngc_environment.tenant_org_name

# Check the initial state is good before we get started
print(f"Checking {machine_under_test} is Ready...")
if not admin_cli.check_machine_ready(machine_under_test):
    print(f"Machine {machine_under_test} is not Ready!", file=sys.stderr)
    sys.exit(1)
print(f"Checking {machine_under_test} is not in maintenance mode...")
if not admin_cli.check_machine_not_in_maintenance(machine_under_test):
    print(f"Machine {machine_under_test} is in Maintenance!", file=sys.stderr)
    sys.exit(1)

# Get DPU BMC credentials out of corp vault
with ForgeVaultClient(path=site_under_test) as vault_client:
    dpu_bmc_username, dpu_bmc_password = vault_client.get_dpu_bmc_credentials()
    host_bmc_username, host_bmc_password = vault_client.get_host_bmc_credentials()

# Get SSH key out of corp vault (vault kv get -mount=secrets forge/machine-lifecycle-test)
with ForgeVaultClient(path="forge/machine-lifecycle-test") as vault_client:
    private_key: str = vault_client.get_ssh_private_key()
with io.StringIO(initial_value=private_key) as ssh_private_key_file:
    ssh_private_key = paramiko.ed25519key.Ed25519Key.from_private_key(ssh_private_key_file)

# Collect DPU machine IDs for later
machine = admin_cli.get_machine(machine_under_test)
host_bmc_ip = machine["host_bmc_ip"]
dpus_under_test: list[str] = []  # list of DPU machine ids (fm100d...)
for dpu in machine["dpus"]:
    dpus_under_test.append(dpu["machine_id"])
print(f"DPUs in this machine: {dpus_under_test}")
# Once we force-delete, we'll have to use a DPU machine ID to look it up until host fully ingested
machine_under_test_dpu = dpus_under_test[0]
machine_under_test_predicted_host = machine_under_test_dpu[0:5] + "p" + machine_under_test_dpu[6:]
# DPU:           fm100dsjdhejja4pme30mnbdc6amjh3lgnpid7kfi1v1gcthj2lea83ssq0
# PredictedHost: fm100psjdhejja4pme30mnbdc6amjh3lgnpid7kfi1v1gcthj2lea83ssq0

# Capture & log machine information before force-delete
print(f"Force deleting {machine_under_test}...")
admin_cli.force_delete_machine(machine_under_test)

# Reset the DPUs
# TODO: This step may become unnecessary once site-explorer is auto-creating machines
for dpu in machine["dpus"]:
    print(f"Resetting DPU {dpu['machine_id']}...")
    with paramiko.SSHClient() as ssh_client:
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(dpu["bmc_ip"], username=dpu_bmc_username, password=dpu_bmc_password)

        command = "echo 'SW_RESET 1' > /dev/rshim0/misc"
        print(f"Executing command: {command}")
        i, o, e = ssh_client.exec_command(command)
        stdout = o.readlines()
        stderr = e.readlines()
        exit_status = o.channel.recv_exit_status()
        if exit_status != 0:
            print(f"{command!r} stdout: {stdout}")
            print(f"{command!r} stderr: {stderr}")
            print(f"{command!r} exited with status {exit_status}", file=sys.stderr)

# Discovery portion.
# If there is a failure anywhere here attempt to put the machine into maintenance mode
# for investigation (this will prevent future runs affecting the machine).
try:
    # Wait up to 1 hour for Host/WaitingForDiscovery
    print(f"Wait for DPU {machine_under_test_dpu} to report state 'Host/WaitingForDiscovery'")
    admin_cli.wait_for_machine_waitingforhostdiscovery(machine_under_test_dpu, timeout=60 * 60)

    # Power cycle host
    print(f"Power host off for a minute and then turn it back on")
    admin_cli.power_off_host(host_bmc_ip, host_bmc_username, host_bmc_password)
    time.sleep(60)
    admin_cli.power_on_host(host_bmc_ip, host_bmc_username, host_bmc_password)

    # Wait for Ready state
    print(f"Wait for DPU {machine_under_test_dpu} to report state 'Ready'")
    admin_cli.wait_for_machine_ready(machine_under_test_dpu, timeout=60 * 90)
except Exception as e:
    print("Exception while waiting for machine Ready, putting machine into maintenance mode", file=sys.stderr)
    # We have to use managed host ID to do this, not DPU ID, but this may not exist
    # in the database yet depending on where the process got to before it failed.
    # If using that doesn't work, try again with the predicted host id.
    try:
        admin_cli.put_machine_into_maintenance_mode(machine_under_test)
    except subprocess.CalledProcessError as e:
        print("Setting maintenance mode failed, trying again using predicted host id...", file=sys.stderr)
        admin_cli.put_machine_into_maintenance_mode(machine_under_test_predicted_host)
    raise

print(f"Check {machine_under_test_dpu} is not in maintenance mode")
admin_cli.check_machine_not_in_maintenance(machine_under_test_dpu)

# Verify that the original machine id is also reporting Ready
print(f"Check managed host id {machine_under_test} also reports ready")
admin_cli.check_machine_ready(machine_under_test)
# Wait for the cloud to also know the machine is Ready before instance creation
print(f"Wait for the cloud to also report {machine_under_test} is ready")
ngc.wait_for_machine_ready(machine_under_test, site, timeout=60 * 10)


# Get required UUIDs from ngc
site_uuid = ngc.get_site_uuid(site.ngc_name)
print(f"{site_uuid=}")
instance_type_uuid = ngc.get_instance_type_uuid("machine-lifecycle-test", site_uuid)
print(f"{instance_type_uuid=}")
subnet_uuid = ngc.get_subnet_uuid("machine-lifecycle-test-subnet")
print(f"{subnet_uuid=}")
os_uuid = ngc.get_operating_system_uuid("machine-lifecycle-test-os")
print(f"{os_uuid=}")
vpc_uuid = ngc.get_virtual_private_cloud_uuid("machine-lifecycle-test-vpc")
print(f"{vpc_uuid=}")

# We could supply --user-data here to customize the OS with our SSH public key direct from vault,
# but we can revisit this if we need to change anything. We expect it to be static.
print("Creating an instance on the machine...")
instance = ngc.create_instance("machine-lifecycle-test-instance", instance_type_uuid, subnet_uuid, os_uuid, vpc_uuid)
instance_uuid = instance["id"]
print(f"Instance {instance_uuid} creation success")
admin_cli.wait_for_machine_assigned_ready(machine_under_test, timeout=60 * 10)

print("Sleeping for 20 minutes for instance installation...")
# The problem is that here, there will be an instance reboot, and we want to wait until
# after that before attempting to test out SSH connection.
time.sleep(60 * 20)

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
print("Delete the instance")
ngc.delete_instance(instance_uuid)

# Wait for the instance to be deleted
print("Wait for the instance to be deleted...")
# TODO: In future, we may want to check that our instance isn't present in the list any more,
#  but for now, since the "demo1-machine-lifecycle-test" compute allocation is 1,
#  checking for an empty list of instances will suffice.
ngc.wait_for_empty_vpc(site_uuid, vpc_uuid, timeout=60 * 90)

# Wait for Ready & out of maintenance (in the case DPU FW upgrade happens after de-provision)
print(f"Wait for {machine_under_test} to report state 'Ready'")
admin_cli.wait_for_machine_ready(machine_under_test, timeout=60 * 90)
print("Wait for the machine to not be in maintenance mode...")
admin_cli.wait_for_machine_not_in_maintenance(machine_under_test, timeout=60 * 90)
print("Final check that the machine is still marked Ready")
admin_cli.check_machine_ready(machine_under_test)
# Wait for the cloud to also report Ready
print(f"Wait for the cloud to also report {machine_under_test} is ready")
ngc.wait_for_machine_ready(machine_under_test, site, timeout=60 * 10)
