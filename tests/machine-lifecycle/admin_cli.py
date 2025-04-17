"""Functions for talking to the forge admin cli utility."""

import datetime
import json
import os
import subprocess
import sys
import time
from json import JSONDecodeError


def wait_for_machine_ready(machine_id: str, timeout: int) -> None:
    """Check repeatedly until the specified machine is in Ready state, for up to `timeout` seconds."""
    wait_for_state(machine_id, "Ready", timeout, allow_missing_machine=True)


def wait_for_machine_assigned_ready(machine_id: str, timeout: int) -> None:
    """Check repeatedly until the specified machine is in Assigned/Ready state, for up to `timeout` seconds."""
    wait_for_state(machine_id, "Assigned/Ready", timeout, allow_missing_machine=True)


def wait_for_machine_hostinitializing(machine_id: str, timeout: int) -> None:
    """Check repeatedly until the specified machine reaches any HostInitializing state, for up to `timeout` seconds."""
    wait_for_state(machine_id, "HostInitializing", timeout, allow_missing_machine=True)


def wait_for_machine_not_in_maintenance(machine_id: str, timeout: int) -> None:
    """Check repeatedly until the specified machine is not in maintenance, for up to `timeout` seconds."""
    end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=timeout)
    while (now := datetime.datetime.now(datetime.timezone.utc)) < end:
        not_in_maintenance = check_machine_not_in_maintenance(machine_id)
        if not_in_maintenance:
            print(f"{now.strftime('%Y-%m-%d %H:%M:%S')}: machine {machine_id} is not in maintenance!")
            return
        else:
            print(f"{now.strftime('%Y-%m-%d %H:%M:%S')}: machine {machine_id} not out of maintenance yet")
            time.sleep(60)
    else:
        raise TimeoutError(f"Machine id {machine_id} still in maintenance after {timeout} seconds")


def wait_for_machine_not_updating(machine_id: str, timeout: int) -> None:
    """Check repeatedly until the specified host is not receiving a DPU FW update from Forge,
    for up to `timeout` seconds.
    """
    end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=timeout)
    while (now := datetime.datetime.now(datetime.timezone.utc)) < end:
        not_updating = check_machine_not_updating(machine_id)
        if not_updating:
            print(f"{now.strftime('%Y-%m-%d %H:%M:%S')}: machine is not receiving a DPU FW update.")
            return
        else:
            print(f"{now.strftime('%Y-%m-%d %H:%M:%S')}: machine is receiving a DPU FW update.")
            time.sleep(60)
    else:
        raise TimeoutError(f"Machine still receiving DPU FW update after {timeout} seconds.")


def wait_for_state(machine_id: str, desired_state: str, timeout: int, allow_missing_machine: bool = False) -> None:
    """Check repeatedly until the specified machine is in a specific state, for up to `timeout` seconds.

    desired_state: Can be a partial state name or a full state name.
    "Failed/Discovery" is a (bad) terminal state.
    If we get in any state starting "Failed", raise an exception to fail fast.
    """
    if not desired_state:
        raise ValueError("No desired state specified")
    end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=timeout)
    while (now := datetime.datetime.now(datetime.timezone.utc)) < end:
        state = get_machine_state(machine_id, allow_missing_machine)
        if state.startswith("Failed"):
            raise Exception(f"Failure! Machine id {machine_id} went into {state}.")
        # Allow partial state names to be queried
        if desired_state in state:
            print(f"{now.strftime('%Y-%m-%d %H:%M:%S')}: machine {machine_id} reached desired state ({desired_state})!")
            return
        else:
            print(
                f"{now.strftime('%Y-%m-%d %H:%M:%S')}: machine {machine_id} not in desired state ({desired_state}) "
                f"yet, current state: {state}"
            )
            time.sleep(60)
    else:
        raise TimeoutError(
            f"Machine id {machine_id} did not get to desired state ({desired_state}) within {timeout} seconds"
        )


def check_machine_ready(machine_id: str) -> bool:
    """Check once if the specified machine is in ready state."""
    state = get_machine_state(machine_id)
    print(f"{machine_id} state '{state}'")
    return state == "Ready"


def get_machine_state(machine_id: str, allow_missing_machine: bool = False) -> str:
    """Get the current state for the specified machine."""
    machine = get_machine_from_m_show(machine_id, allow_missing_machine)
    if machine is None and allow_missing_machine:
        print(f"Machine with id {machine_id} not found, retry later.")
        return "<Missing>"
    return machine["state"]


def get_machine_vendor(machine_id: str) -> str:
    """Get the vendor name of the specified machine."""
    result = run_forge_admin_cli(["machine", "show", machine_id])
    return result['discovery_info']['dmi_data']['sys_vendor']


def _get_machine_from_json(machine_id: str, machine_json: dict) -> dict | None:
    """Given JSON managed-host show output, return just the machine we want.

    Can provide any type of machine_id (Host, DPU, PredictedHost).
    If the machine is not found, return None.
    """
    if len(machine_id) < 6:
        raise ValueError(f"Invalid machine id: '{machine_id}'")
    if machine_id[5] in "hp":
        # Host or PredictedHost
        try:
            return [mach for mach in machine_json if mach["machine_id"] == machine_id][0]
        except IndexError:
            return None

    elif machine_id[5] == "d":
        # DPU
        for mach in machine_json:
            for dpu in mach["dpus"]:
                if dpu["machine_id"] == machine_id:
                    return mach
        else:
            return None


def check_machine_not_updating(host_id: str) -> bool:
    """Check once if the specified host is receiving a DPU FW update from Forge. This is indicated by a
    health alert labelled with id 'HostUpdateInProgress'.

    :param host_id: Note: must not be the DPU ID
    """
    update_alert = "HostUpdateInProgress"
    machine = get_machine_from_mh_show(host_id)
    health_alerts = [alert["id"] for alert in machine["health"]["alerts"]]
    return update_alert not in health_alerts


def check_machine_not_in_maintenance(machine_id: str) -> bool:
    """Check once if the specified machine is in ready state."""
    machine = get_machine_from_mh_show(machine_id)
    print(
        f"{machine_id} maintenance_start_time '{machine['maintenance_start_time']}'"
        f" maintenance_reference '{machine['maintenance_reference']}'"
    )
    return machine["maintenance_start_time"] is None


def put_machine_into_maintenance_mode(machine_id: str) -> None:
    """Put the specified machine into maintenance mode.

    Note: ngc can also put a machine into maintenance mode but that turned out
    not to be very useful for machine lifecycle testing because the cloud can
    only put a machine into maintenance mode if it knows about the machine.
    There are many states we can get into where this is not the case.
    """
    if os.environ.get("CI", "false") == "true":
        job_name = os.environ.get("CI_JOB_NAME", "Unknown Job Name")
        job_url = os.environ.get("CI_JOB_URL", "Unknown Job URL")
        reason = f"CI job '{job_name}' requested maintenance mode ({job_url})"
    else:
        reason = "Maintenance requested via tests/machine-lifecycle/admin_cli.py"
    run_forge_admin_cli(
        ["managed-host", "maintenance", "on", "--host", machine_id, "--reference", reason], no_json=True
    )


def get_machine_from_mh_show(machine_id: str, allow_missing: bool = False) -> dict | None:
    """Get JSON formatted machine information from `managed-host show` output.
    This will only work after the host and DPU have been paired to create a managed host."""
    result = run_forge_admin_cli(["managed-host", "show"])
    machine = _get_machine_from_json(machine_id, result)
    if machine is None:
        if not allow_missing:
            raise Exception(f"Machine with id {machine_id} not found.")
    return machine


def get_machine_from_m_show(machine_id: str, allow_missing: bool = False) -> dict | None:
    """Get JSON formatted machine information from `machine show` output.
    This will work at any point once the machine has been discovered and given an ID"""
    try:
        machine = run_forge_admin_cli(["machine", "show", machine_id])
    except subprocess.CalledProcessError:
        if allow_missing:
            return None
        raise Exception(f"Machine with id {machine_id} not found.")
    return machine


def force_delete_machine(machine_id: str, delete_creds: bool = False) -> None:
    """Force-delete the specified machine.

    Enable `delete_creds` if the machine has been factory-reset, to delete the creds from Vault.
    Always print out the machine information first.
    """
    print("Machine information before force-delete:")
    run_forge_admin_cli(["managed-host", "show", machine_id], no_json=True)

    print("Performing force-delete...")
    args = ["machine", "force-delete"]
    if delete_creds:
        args.extend(["--delete-bmc-credentials"])
    args.extend(["--machine", machine_id])
    run_forge_admin_cli(args, no_json=True)


def power_off_host(host_bmc_ip: str, host_bmc_username: str, host_bmc_password: str) -> None:
    """Power off a machine using redfish."""
    print("Performing host redfish force-off")
    run_forge_admin_cli(
        [
            "redfish",
            "--address",
            host_bmc_ip,
            "--username",
            host_bmc_username,
            "--password",
            host_bmc_password,
            "force-off",
        ],
        no_json=True,
    )


def power_on_host(host_bmc_ip: str, host_bmc_username: str, host_bmc_password: str) -> None:
    """Power on a machine using redfish."""
    print("Performing host redfish on")
    run_forge_admin_cli(
        [
            "redfish",
            "--address",
            host_bmc_ip,
            "--username",
            host_bmc_username,
            "--password",
            host_bmc_password,
            "on",
        ],
        no_json=True,
    )


def restart_machine(machine_id: str) -> None:
    """Restart a machine (host or DPU) via redfish ForceRestart"""
    run_forge_admin_cli(
        [
            "machine",
            "reboot",
            "--machine",
            machine_id,
        ],
        no_json=True,
    )


def clear_host_bios_password(machine_id: str) -> None:
    """Remove the BIOS password from a host"""
    run_forge_admin_cli(["host", "clear-uefi-password", "--query", machine_id], no_json=True)


def restart_bmc(machine_id: str) -> None:
    """Restart a BMC (DPU or host)."""
    run_forge_admin_cli(
        [
            "bmc-machine",
            "bmc-reset",
            "--machine",
            machine_id,
        ],
        no_json=True,
    )


def factory_reset_bmc(bmc_ip: str, bmc_username: str, bmc_password: str) -> None:
    """Factory-reset a BMC (DPU or host) to defaults via redfish."""
    run_forge_admin_cli(
        [
            "redfish",
            "bmc-reset-to-defaults",
            "--address",
            bmc_ip,
            "--username",
            bmc_username,
            "--password",
            bmc_password,
        ],
        no_json=True,
    )


def run_forge_admin_cli(args: list[str], no_json: bool = False) -> dict | None:
    """Run the specified forge-admin-cli command.

    Specify arguments as a list.
    Set no_json to True if the command doesn't support the json output format.
    In that case, this function will return rather than the JSON object.

    :raises subprocess.CalledProcessError: If the command fails.
    """
    command = ["forge-admin-cli"]
    if not no_json:
        command.extend(["--format", "json"])
    command.extend(args)

    print(f"Executing {command}")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.stderr:
        print(f"stderr: {result.stderr}")
    result.check_returncode()

    if no_json:
        print(result.stdout)
        return None

    try:
        json_result = json.loads(result.stdout)
    except JSONDecodeError:
        print(f"JSON decode error:\n{result.stdout}", file=sys.stderr)
        raise
    else:
        return json_result
