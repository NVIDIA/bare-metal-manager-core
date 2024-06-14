"""Functions for talking to the ngc cli utility."""

import datetime
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from json import JSONDecodeError
from typing import Literal


@dataclass
class Environment:
    name: str
    api_url: str
    tenant_org_name: str
    provider_org_name: str


ENVS: dict[str, Environment] = {
    "prod": Environment("prod", "https://api.ngc.nvidia.com", "i1k1exmxlqr1", "qpbftykv9atm"),
    "stg": Environment("stg", "https://api.stg.ngc.nvidia.com", "fh93zk6uqtt1", "wdksahew1rqv"),
}


@dataclass
class Site:
    name: str
    environment: Literal["prod", "stg"]
    ngc_name: str = None

    def __post_init__(self):
        if self.ngc_name is None:
            self.ngc_name = self.name  # Most sites don't have a different name in ngc


class ForgeNGCError(Exception):
    """Exception for Forge NGC CLI related errors"""


def get_site_uuid(site_name: str) -> str:
    """Given a site name, find its UUID."""
    ngc_command = ["ngc", "--format_type", "json", "forge", "site", "list"]
    print(f"Executing {ngc_command}")
    ngc_process = subprocess.run(ngc_command, capture_output=True, text=True)
    if ngc_process.returncode:
        print(f"ngc stdout: {ngc_process.stdout}")
        print(f"ngc stderr: {ngc_process.stderr}")
    ngc_process.check_returncode()
    data = json.loads(ngc_process.stdout)
    for item in data:
        if item.get("name") == site_name:
            item_id = item["id"]
            return item_id
    else:
        raise ForgeNGCError(f"No site with name '{site_name}' found.")


def get_instance_type_uuid(instance_type_name: str, site_uuid: str) -> str:
    """Given a site UUID and an instance type name, find its UUID."""
    ngc_command = ["ngc", "--format_type", "json", "forge", "instance-type", "list", "--site", site_uuid]
    print(f"Executing {ngc_command}")
    ngc_process = subprocess.run(ngc_command, capture_output=True, text=True)
    if ngc_process.returncode:
        print(f"ngc stdout: {ngc_process.stdout}")
        print(f"ngc stderr: {ngc_process.stderr}")
    ngc_process.check_returncode()
    data = json.loads(ngc_process.stdout)
    for item in data:
        if item.get("name") == instance_type_name:
            item_id = item["id"]
            return item_id
    else:
        raise ForgeNGCError(f"No instance type with name '{instance_type_name}' in site '{site_uuid}' found.")


def get_subnet_uuid(subnet_name: str) -> str:
    """Given a subnet name, find its UUID."""
    ngc_command = ["ngc", "--format_type", "json", "forge", "subnet", "list"]
    print(f"Executing {ngc_command}")
    ngc_process = subprocess.run(ngc_command, capture_output=True, text=True)
    if ngc_process.returncode:
        print(f"ngc stdout: {ngc_process.stdout}")
        print(f"ngc stderr: {ngc_process.stderr}")
    ngc_process.check_returncode()
    data = json.loads(ngc_process.stdout)
    for item in data:
        if item.get("name") == subnet_name:
            item_id = item["id"]
            return item_id
    else:
        raise ForgeNGCError(f"No subnet with name '{subnet_name}' found.")


def get_operating_system_uuid(operating_system_name: str) -> str:
    """Given an operating system name, find its UUID."""
    ngc_command = ["ngc", "--format_type", "json", "forge", "operating-system", "list"]
    print(f"Executing {ngc_command}")
    ngc_process = subprocess.run(ngc_command, capture_output=True, text=True)
    if ngc_process.returncode:
        print(f"ngc stdout: {ngc_process.stdout}")
        print(f"ngc stderr: {ngc_process.stderr}")
    ngc_process.check_returncode()
    data = json.loads(ngc_process.stdout)
    for item in data:
        if item.get("name") == operating_system_name:
            item_id = item["id"]
            return item_id
    else:
        raise ForgeNGCError(f"No operating system with name '{operating_system_name}' found.")


def get_virtual_private_cloud_uuid(vpc_name: str) -> str:
    """Given a Virtual Private Cloud name, find its UUID."""
    ngc_command = ["ngc", "--format_type", "json", "forge", "vpc", "list"]
    print(f"Executing {ngc_command}")
    ngc_process = subprocess.run(ngc_command, capture_output=True, text=True)
    if ngc_process.returncode:
        print(f"ngc stdout: {ngc_process.stdout}")
        print(f"ngc stderr: {ngc_process.stderr}")
    ngc_process.check_returncode()
    data = json.loads(ngc_process.stdout)
    for item in data:
        if item.get("name") == vpc_name:
            item_id = item["id"]
            return item_id
    else:
        raise ForgeNGCError(f"No Virtual Private Cloud with name '{vpc_name}' found.")


def wait_for_machine_ready(machine_id: str, site: Site, timeout: int) -> None:
    """Check repeatedly until the specified machine has status Ready, for up to `timeout` seconds."""
    wait_for_machine_status(machine_id, site, "Ready", timeout)


def wait_for_machine_status(
    machine_id: str, site: Site, desired_status: str, timeout: int, allow_missing_machine: bool = False
) -> None:
    """Check repeatedly until the specified machine has a specific status, for up to `timeout` seconds."""
    end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=timeout)
    while (now := datetime.datetime.now(datetime.timezone.utc)) < end:
        status = get_machine_status(machine_id, site, allow_missing_machine)
        if status == desired_status:
            print(f"{now}: machine {machine_id} reached desired status ({desired_status})!")
            return
        else:
            print(f"{now}: machine {machine_id} not in desired status ({desired_status}) yet, current status: {status}")
            time.sleep(60)
    else:
        raise TimeoutError(
            f"Machine id {machine_id} did not get to desired status ({desired_status}) within {timeout} seconds"
        )


def get_machine_status(machine_id: str, site: Site, allow_missing_machine: bool = False) -> str:
    """Get the current status of the specified machine.

    If the machine doesn't exist, and allow_missing_machine is True,
    assume that it is expected to exist in the future and return "<Missing>".
    """
    ngc_command = [
        "ngc",
        "--format_type",
        "json",
        "forge",
        "machine",
        "info",
        "--org",
        ENVS[site.environment].provider_org_name,
        machine_id,
    ]
    print(f"Executing {ngc_command}")
    ngc_process = subprocess.run(ngc_command, capture_output=True, text=True)
    if ngc_process.returncode == 1 and "Client Error: 404 Response" in ngc_process.stderr and allow_missing_machine:
        return "<Missing>"
    elif ngc_process.returncode:
        print(f"machine info stdout: {ngc_process.stdout}")
        print(f"machine info stderr: {ngc_process.stderr}")
    ngc_process.check_returncode()

    try:
        data = json.loads(ngc_process.stdout)
    except JSONDecodeError:
        print(f"JSON decode error:\n{ngc_process.stdout}", file=sys.stderr)
        raise
    else:
        return data["status"]


def create_instance(
    instance_name: str,
    instance_type_uuid: str,
    subnet_uuid: str,
    operating_system_uuid: str,
    virtual_private_cloud_uuid: str,
) -> dict:
    """Create an instance with the given name.

    The JSON response from ngc is returned.
    """
    ngc_command = [
        "ngc",
        "--format_type",
        "json",
        "forge",
        "instance",
        "create",
        "--instance-type",
        instance_type_uuid,
        "--interface",
        subnet_uuid,
        "--operating-system",
        operating_system_uuid,
        "--vpc",
        virtual_private_cloud_uuid,
        instance_name,
    ]
    print(f"Executing {ngc_command}")
    ngc_process = subprocess.run(ngc_command, capture_output=True, text=True)
    if ngc_process.returncode:
        print(f"ngc stdout: {ngc_process.stdout}")
        print(f"ngc stderr: {ngc_process.stderr}")
    ngc_process.check_returncode()

    print("instance create stdout:")
    print(ngc_process.stdout)
    print("instance create stderr:")
    print(ngc_process.stderr)
    try:
        data = json.loads(ngc_process.stdout)
    except JSONDecodeError:
        print(f"JSON decode error:\n{ngc_process.stdout}", file=sys.stderr)
        raise
    else:
        return data


def get_instance_info(instance_uuid: str) -> dict:
    """Get up-to-date info on the instance with the given UUID."""
    ngc_command = ["ngc", "--format_type", "json", "forge", "instance", "info", instance_uuid]
    print(f"Executing {ngc_command}")
    ngc_process = subprocess.run(ngc_command, capture_output=True, text=True)
    if ngc_process.returncode:
        print(f"ngc stdout: {ngc_process.stdout}")
        print(f"ngc stderr: {ngc_process.stderr}")
    ngc_process.check_returncode()
    try:
        data = json.loads(ngc_process.stdout)
    except JSONDecodeError:
        print(f"JSON decode error:\n{ngc_process.stdout}", file=sys.stderr)
        raise
    else:
        return data


def wait_for_instance_ip(instance_uuid: str, subnet_uuid: str, timeout: int) -> str:
    """Wait until the given instance has an IP address.

    During/after instance creation, we will have to wait for the IP address to be populated.
    """
    end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=timeout)
    while (now := datetime.datetime.now(datetime.timezone.utc)) < end:
        ip_address = get_instance_ip(instance_uuid, subnet_uuid)
        if ip_address:
            return ip_address
        else:
            print(f"{now}: Instance {instance_uuid} doesn't have an IP address yet")
            time.sleep(60)
    else:
        raise TimeoutError(f"Instance {instance_uuid} did not get an IP address empty within {timeout} seconds.")


def get_instance_ip(instance_uuid: str, subnet_uuid: str) -> str | None:
    """Get an instance's IP address on the specified subnet.

    Assumes there is only one IP address for the subnet on the instance.
    If the instance doesn't have an IP address (yet) return None.
    """
    data = get_instance_info(instance_uuid)
    for interface in data["interfaces"]:
        if interface["subnetId"] == subnet_uuid:
            if interface["ipAddresses"] is not None:
                return interface["ipAddresses"][0]
            else:
                return None
    else:
        print(f"Couldn't find details for subnet '{subnet_uuid}'.\n{data}", file=sys.stderr)
        return None


def delete_instance(instance_uuid: str) -> None:
    """Delete the instance with the given UUID."""
    ngc_command = ["ngc", "forge", "instance", "remove", instance_uuid]
    print(f"Executing {ngc_command}")
    ngc_process = subprocess.run(ngc_command, capture_output=True, text=True)
    if ngc_process.returncode:
        print(f"ngc stdout: {ngc_process.stdout}")
        print(f"ngc stderr: {ngc_process.stderr}")
    ngc_process.check_returncode()


def get_instances(site_uuid: str, vpc_uuid: str = None) -> list[dict]:
    """Get instance details for a site.

    Optionally provide a Virtual Private Cloud's UUID to only show instance in that VPC.
    """
    ngc_command = ["ngc", "--format_type", "json", "forge", "instance", "list", "--site", site_uuid]
    if vpc_uuid is not None:
        ngc_command += ["--vpc", vpc_uuid]
    print(f"Executing {ngc_command}")
    ngc_process = subprocess.run(ngc_command, capture_output=True, text=True)
    if ngc_process.returncode:
        print(f"ngc stdout: {ngc_process.stdout}")
        print(f"ngc stderr: {ngc_process.stderr}")
    ngc_process.check_returncode()

    try:
        data = json.loads(ngc_process.stdout)
    except JSONDecodeError:
        print(f"JSON decode error:\n{ngc_process.stdout}", file=sys.stderr)
        raise
    else:
        return data


def wait_for_empty_vpc(site_uuid: str, vpc_uuid: str, timeout: int) -> None:
    """Wait until the specified Virtual Private Network has no instances."""
    instances = None
    end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=timeout)
    while (now := datetime.datetime.now(datetime.timezone.utc)) < end:
        instances = get_instances(site_uuid, vpc_uuid)
        if not instances:
            print(f"{now}: VPC {vpc_uuid} has no instances!")
            return
        else:
            print(f"{now}: VPC {vpc_uuid} still has {len(instances)} instances")
            time.sleep(60)
    else:
        raise TimeoutError(f"VPC {vpc_uuid} did not become empty within {timeout} seconds.\n{instances}")
