"""Functions for talking to the forge admin cli utility."""

import datetime
import json
import os
import subprocess
import sys
import time
from json import JSONDecodeError

from rich import print_json


def wait_for_machine_ready(machine_id: str, timeout: int) -> None:
    """Check repeatedly until the specified machine is in Ready state, for up to `timeout` seconds."""
    wait_for_state(machine_id, "Ready", timeout)


def wait_for_machine_assigned_ready(machine_id: str, timeout: int) -> None:
    """Check repeatedly until the specified machine is in Assigned/Ready state, for up to `timeout` seconds."""
    wait_for_state(machine_id, "Assigned/Ready", timeout)


def wait_for_machine_waitingforhostdiscovery(machine_id: str, timeout: int) -> None:
    """Check repeatedly until the specified machine is in Host/WaitingForDiscovery state, for up to `timeout` seconds."""
    wait_for_state(machine_id, "Host/WaitingForDiscovery", timeout, allow_missing_machine=True)


def wait_for_machine_not_in_maintenance(machine_id: str, timeout: int) -> None:
    """Check repeatedly until the specified machine is not in maintenance, for up to `timeout` seconds."""
    end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=timeout)
    while (now := datetime.datetime.now(datetime.timezone.utc)) < end:
        not_in_maintenance = check_machine_not_in_maintenance(machine_id)
        if not_in_maintenance:
            print(f"{now}: machine {machine_id} is not in maintenance!")
            return
        else:
            print(f"{now}: machine {machine_id} not out of maintenance yet")
            time.sleep(60)
    else:
        raise TimeoutError(f"Machine id {machine_id} still in maintenance after {timeout} seconds")


def wait_for_state(machine_id: str, desired_state: str, timeout: int, allow_missing_machine: bool = False) -> None:
    """Check repeatedly until the specified machine is in a specific state, for up to `timeout` seconds.

    "Failed/Discovery" is a (bad) terminal state.
    If we get in any state starting "Failed", raise an exception to fail fast.
    """
    end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=timeout)
    while (now := datetime.datetime.now(datetime.timezone.utc)) < end:
        state = get_machine_state(machine_id, allow_missing_machine)
        if state.startswith("Failed"):
            raise Exception(f"Failure! Machine id {machine_id} went into {state}.")
        if state == desired_state:
            print(f"{now}: machine {machine_id} reached desired state ({desired_state})!")
            return
        else:
            print(f"{now}: machine {machine_id} not in desired state ({desired_state}) yet, current state: {state}")
            time.sleep(60)
    else:
        raise TimeoutError(
            f"Machine id {machine_id} did not get to desired state ({desired_state}) within {timeout} seconds"
        )


def check_machine_ready(machine_id: str) -> bool:
    """Check once if the specified machine is in ready state."""
    state = get_machine_state(machine_id)
    return state == "Ready"


def get_machine_state(machine_id: str, allow_missing_machine: bool = False) -> str:
    """Get the current state for the specified machine."""
    machine = get_machine(machine_id, allow_missing_machine)
    if machine is None and allow_missing_machine:
        print(f"Machine with id {machine_id} not found, retry later.")
        return "<Missing>"
    return machine["state"]


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


def check_machine_not_in_maintenance(machine_id: str) -> bool:
    """Check once if the specified machine is in ready state."""
    machine = get_machine(machine_id)
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
        reason = f"Maintenance requested via tests/machine-lifecycle/admin_cli.py"
    run_forge_admin_cli(
        ["managed-host", "maintenance", "on", "--host", machine_id, "--reference", reason], no_json=True
    )


def get_machine(machine_id: str, allow_missing: bool = False) -> dict | None:
    """Get JSON formatted machine information."""
    result = run_forge_admin_cli(["managed-host", "show"])
    machine = _get_machine_from_json(machine_id, result)
    if machine is None:
        if not allow_missing:
            raise Exception(f"Machine with id {machine_id} not found.\n{result}")
    return machine


def force_delete_machine(machine_id: str) -> None:
    """Force-delete the specified machine.

    Always print out the machine information first.
    """
    machine = get_machine(machine_id)
    print("Machine information before force-delete:")
    print_json(data=machine)

    print("Performing force-delete...")
    run_forge_admin_cli(["machine", "force-delete", "--machine", machine_id], no_json=True)


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
    """Power pn a machine using redfish."""
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
    result = subprocess.run(command, capture_output=True)
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
