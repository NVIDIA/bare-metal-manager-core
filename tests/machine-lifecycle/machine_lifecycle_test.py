import io
import os
import pprint
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Literal
import uuid
import paramiko
import requests
import urllib3

import admin_cli
import network
import ngc
import config
import utils
from vault import ForgeVaultClient

import capability_validator
import capabilities_generator
from dell_factory_reset import DellFactoryResetMethods

urllib3.disable_warnings()

# Available DPU firmware versions to which to downgrade
SUPPORTED_FW_VERSIONS_FOR_DOWNGRADE = {
    "2.2.1": config.DOCA_2_2_1,
    "2.5.0": config.DOCA_2_5_0,
}


@dataclass
class TestConfig:
    """Configuration for the machine lifecycle test."""

    site_under_test: str
    short_site_name: str
    machine_under_test: str
    machine_sku: str | None
    expected_dpu_count: int
    dpu_fw_downgrade: bool
    fw_downgrade_version: str | None
    provision_cycles: int
    skip_factory_reset: bool
    debug_ingestion_only: bool
    debug_instance_provision_only: bool


@dataclass
class SiteConfig:
    """Configuration for the site and NGC environment."""

    site: ngc.Site
    ngc_api_key: str
    dpu_bmc_username: str
    dpu_bmc_password: str
    host_bmc_password: str


@dataclass
class MachineInfo:
    """Information about the machine under test."""

    machine: dict
    vendor: Literal["lenovo", "dell"]  # Currently supported for these tests
    host_bmc_username: str
    host_bmc_ip: str
    host_bmc_mac: str
    dpu_ids: list[str]
    dpu_bmc_ips: list[str]
    dpu_info_map: dict[str, dict[str, str]]
    dpu_model: str
    machine_under_test_dpu: str
    machine_under_test_predicted_host: str


@dataclass
class NGCUUIDs:
    """UUIDs required for NGC operations."""

    site_uuid: str
    instance_type_uuid: str
    vpc_uuid: str
    subnet_uuid: str
    os_uuid: str


@dataclass
class FirmwarePaths:
    """Paths to the local downloaded firmware files."""

    bmc_fw_path: str
    cec_fw_path: str
    bfb_path: str


def main():
    """Main entry point for the machine lifecycle test."""

    ##################################
    # 1. Setup and log initial state #
    ##################################
    test_config = setup_test_config()
    pprint.pprint(test_config)
    site_config = setup_site_config(test_config)
    pprint.pprint(_mask_site_config_creds(site_config))
    machine_info = collect_machine_info(test_config)
    ngc_uuids = collect_ngc_uuids(test_config, site_config)

    # Check machine is in a testable state
    verify_initial_machine_state(test_config)

    # Collect initial machine capabilities (currently only tested in QA2)
    machine_capabilities = ""
    if test_config.site_under_test == "pdx-qa2-new":
        machine_capabilities = capabilities_generator.generate_capabilities(
            [test_config.machine_under_test]
        )

    if not test_config.debug_instance_provision_only:

        ###########################################
        # 2. Firmware downgrade DPU(s) (OPTIONAL) #
        ###########################################
        if test_config.dpu_fw_downgrade:
            perform_firmware_downgrade(test_config, site_config, machine_info)
            verify_firmware_versions(test_config, site_config, machine_info, downgraded=True)

        ####################################
        # 3. Factory reset host and DPU(s) #
        ####################################
        # NB: This is non-optional if the firmware downgrade has run (see setup_test_config())
        if not test_config.skip_factory_reset:
            perform_factory_reset(test_config, site_config, machine_info)

        ###########################
        # 4. Force delete machine #
        ###########################
        # Unassign any instance type first or force-delete will fail
        ngc.delete_allocation(
            site_config.site,
            f"machine-lifecycle-test-{test_config.machine_sku}",
            strict=False,
        )
        ngc.unassign_instance_type(site_config.site, test_config.machine_under_test, strict=False)

        try:
            # Perform force delete and wait for reingestion to Ready state
            force_delete_and_await_reingestion(test_config, site_config, machine_info)

            # If we performed a downgrade before reingestion, verify firmware has been upgraded by Forge
            if test_config.dpu_fw_downgrade:
                verify_firmware_versions(test_config, site_config, machine_info, downgraded=False)

            # Validate machine capabilities after ingestion (currently only tested in QA2)
            if test_config.site_under_test == "pdx-qa2-new":
                capability_validator.validate_machine_capabilities(
                    test_config.machine_under_test, machine_capabilities, admin_cli
                )
        finally:
            # Attempt to re-assign the instance type even if we hit a failure above.
            # This is a best-effort at keeping the machine marked as 'reserved'.
            ngc.assign_instance_type(
                site_config.site,
                ngc_uuids.instance_type_uuid,
                test_config.machine_under_test,
                strict=False,
            )

    else:
        print("Skipping ingestion portion due to $DEBUG_INSTANCE_PROVISION_ONLY flag")

    if not test_config.debug_ingestion_only:

        ####################################
        # 5. Create and delete an instance #
        ####################################
        # First ensure the machine is assigned and allocated to the tenant
        ngc.assign_instance_type(
            site_config.site,
            ngc_uuids.instance_type_uuid,
            test_config.machine_under_test,
            strict=False,
        )
        ngc.create_allocation(
            site_config.site,
            ngc_uuids.instance_type_uuid,
            ngc_uuids.site_uuid,
            f"machine-lifecycle-test-{test_config.machine_sku}",
            strict=False,
        )

        for i in range(test_config.provision_cycles):
            print(f"Running instance provision cycle {i+1} of {test_config.provision_cycles}")
            instance_uuid = create_instance_and_verify(test_config, site_config, ngc_uuids)
            delete_instance_and_verify(test_config, ngc_uuids, instance_uuid)
    else:
        print("Skipping instance provision portion due to $DEBUG_INGESTION_ONLY flag")


def _mask_site_config_creds(site_config: SiteConfig) -> dict:
    """Create a printable version of site_config with sensitive fields masked."""
    return {
        "site": site_config.site,
        "ngc_api_key": "***masked***",
        "dpu_bmc_username": site_config.dpu_bmc_username,
        "dpu_bmc_password": "***masked***",
        "host_bmc_password": "***masked***",
    }


def _error_and_exit(
    message: str, set_maintenance: bool = False, machine_id: str | None = None
) -> None:
    """Print error message and exit with status code 1.

    Args:
        message: The error message to print
        set_maintenance: Whether to put the machine into maintenance mode before exiting
        machine_id: The ID of the machine to put into maintenance mode if set_maintenance is True
    """
    print(f"ERROR: {message}\nExiting...", file=sys.stderr)
    if set_maintenance and machine_id:
        try:
            admin_cli.put_machine_into_maintenance_mode(machine_id)
        except Exception as e:
            print(f"Failed to put machine into maintenance mode: {e}", file=sys.stderr)
    sys.exit(1)


def setup_test_config() -> TestConfig:
    """Validate test parameters and setup configuration.

    Returns:
        TestConfig: Validated configuration for the test
    """
    # Validate test parameters
    site_under_test = os.environ.get("SITE_UNDER_TEST")  # e.g. "reno-dev4"
    if site_under_test is None:
        _error_and_exit("$SITE_UNDER_TEST must be provided")
    short_site_name = site_under_test.split("-")[1]

    machine_under_test = os.environ.get("MACHINE_UNDER_TEST")  # i.e. a machine id
    if machine_under_test is None:
        _error_and_exit("$MACHINE_UNDER_TEST must be provided")

    machine_sku = os.environ.get("MACHINE_SKU", None)

    expected_dpu_count = int(os.environ.get("DPU_COUNT"))
    if not expected_dpu_count:
        _error_and_exit("$DPU_COUNT must be provided")

    try:
        dpu_fw_downgrade = os.environ.get("FW_DOWNGRADE", "false").lower() == "true"
        fw_downgrade_version = os.environ.get("FW_DOWNGRADE_VERSION", None)
        if dpu_fw_downgrade:
            if fw_downgrade_version is None:
                _error_and_exit(
                    "$FW_DOWNGRADE_VERSION must be provided when $FW_DOWNGRADE is 'true'"
                )
            if fw_downgrade_version not in SUPPORTED_FW_VERSIONS_FOR_DOWNGRADE:
                _error_and_exit(
                    "$FW_DOWNGRADE_VERSION currently only supports '2.2.1' or '2.5.0' (DOCA)"
                )

        skip_factory_reset = os.environ.get("SKIP_FACTORY_RESET", "false").lower() == "true"
        if skip_factory_reset and dpu_fw_downgrade:
            _error_and_exit("$SKIP_FACTORY_RESET can't be 'true' when $FW_DOWNGRADE is 'true'")

        provision_cycles = int(os.environ.get("PROVISION_CYCLES", "1"))

        # DEBUG FLAGS - Choose to run ingestion OR provisioning independently
        debug_ingestion_only = os.environ.get("DEBUG_INGESTION_ONLY", "false").lower() == "true"
        debug_instance_provision_only = (
            os.environ.get("DEBUG_INSTANCE_PROVISION_ONLY", "false").lower() == "true"
        )
        if debug_ingestion_only and debug_instance_provision_only:
            _error_and_exit(
                "$DEBUG_INGESTION_ONLY and $DEBUG_INSTANCE_PROVISION_ONLY cannot both be 'true'"
            )
    except Exception as e:
        _error_and_exit(f"Error setting environment variables: {e}")

    # Set env var for use by forge-admin-cli
    if site_under_test == "reno-qa3":
        os.environ["CARBIDE_API_URL"] = f"https://api-{site_under_test}.frg.nvidia.com"
    else:
        os.environ["CARBIDE_API_URL"] = f"https://api-{short_site_name}.frg.nvidia.com"

    return TestConfig(
        site_under_test=site_under_test,
        short_site_name=short_site_name,
        machine_under_test=machine_under_test,
        expected_dpu_count=expected_dpu_count,
        dpu_fw_downgrade=dpu_fw_downgrade,
        fw_downgrade_version=fw_downgrade_version,
        machine_sku=machine_sku,
        provision_cycles=provision_cycles,
        skip_factory_reset=skip_factory_reset,
        debug_ingestion_only=debug_ingestion_only,
        debug_instance_provision_only=debug_instance_provision_only,
    )


def setup_site_config(test_config: TestConfig) -> SiteConfig:
    """Set up site and NGC configuration.

    Args:
        test_config: The test configuration containing site information
    Returns:
        SiteConfig: Configuration for the site and NGC environment
    """
    sites = [
        ngc.Site("pdx-demo1", "prod"),
        ngc.Site("pdx-dev3", "stg"),
        ngc.Site("reno-dev4", "stg"),
        ngc.Site("pdx-qa2-new", "qa"),
        ngc.Site("reno-qa3", "canary"),
    ]

    # Find out if the selected site is in prod/staging/canary and
    # get the relevant NGC API key from corp vault
    try:
        site = [_site for _site in sites if _site.name == test_config.site_under_test][0]
    except IndexError:
        _error_and_exit(f"Site {test_config.site_under_test} unknown")

    with ForgeVaultClient(path="forge/tokens") as vault_client:
        ngc_api_key = vault_client.get_ngc_api_key(site.environment)

    # Get the site-wide BMC creds from corp vault
    site_vault_path = test_config.site_under_test.replace("-new", "")  # formatting for pdx-qa2-new
    with ForgeVaultClient(path=site_vault_path) as vault_client:
        dpu_bmc_username, dpu_bmc_password = vault_client.get_dpu_bmc_credentials()
        host_bmc_password = vault_client.get_host_bmc_password()

    # Set env vars for use by NGC CLI
    ngc_environment = ngc.ENVS[site.environment]
    os.environ["NGC_CLI_API_URL"] = ngc_environment.api_url
    os.environ["NGC_CLI_API_KEY"] = ngc_api_key
    os.environ["NGC_CLI_ORG"] = ngc_environment.tenant_org_name
    os.environ["NGC_CLI_DEBUG_LOG"] = "ngc_cli_debug.log"

    return SiteConfig(
        site=site,
        ngc_api_key=ngc_api_key,
        dpu_bmc_username=dpu_bmc_username,
        dpu_bmc_password=dpu_bmc_password,
        host_bmc_password=host_bmc_password,
    )


def collect_machine_info(test_config: TestConfig) -> MachineInfo:
    """Collect and validate information about the machine before running the test.

    Args:
        test_config: The test configuration containing machine information
    Returns:
        MachineInfo: Information about the machine under test
    """
    machine = admin_cli.get_machine_from_mh_show(test_config.machine_under_test)
    machine_vendor = admin_cli.get_machine_vendor(test_config.machine_under_test)
    if "lenovo" in machine_vendor.lower():
        vendor = "lenovo"
    elif "dell" in machine_vendor.lower():
        vendor = "dell"
    else:
        vendor = ""  # make linter happy
        _error_and_exit(f"{machine_vendor=} is not valid. Expected to contain 'Lenovo' or 'Dell'")

    print(f"Machine vendor is {vendor}")

    host_bmc_username = "USERID" if vendor == "lenovo" else "root"
    host_bmc_ip = machine["host_bmc_ip"]
    host_bmc_mac = machine["host_bmc_mac"]
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
            dpu_info_map[dpu_id] = {"bmc_ip": bmc_ip, "oob_ip": oob_ip}
        else:
            _error_and_exit(f"Missing data for DPU {dpu_id}")

    # Confirm we found the expected number of DPUs
    if len(dpu_info_map) != test_config.expected_dpu_count:
        _error_and_exit(
            f"Found {len(dpu_info_map)} DPU(s) but expected {test_config.expected_dpu_count}"
        )
    print(f"DPUs in this machine: {dpu_info_map}")

    dpu_model = admin_cli.get_dpu_model(
        dpu_ids[0]
    )  # Multi-DPUs can be assumed to be of same model (i.e. BF2 or BF3)
    if dpu_model.startswith("BlueField SoC") and test_config.dpu_fw_downgrade:
        _error_and_exit("FW_DOWNGRADE option is not supported for BlueField-2 DPUs")

    # After force-delete, we'll use the (first) DPU to track state until the host is fully ingested
    machine_under_test_dpu = dpu_ids[0]
    machine_under_test_predicted_host = (
        machine_under_test_dpu[0:5] + "p" + machine_under_test_dpu[6:]
    )

    return MachineInfo(
        machine=machine,
        vendor=vendor,
        host_bmc_username=host_bmc_username,
        host_bmc_ip=host_bmc_ip,
        host_bmc_mac=host_bmc_mac,
        dpu_ids=dpu_ids,
        dpu_bmc_ips=dpu_bmc_ips,
        dpu_info_map=dpu_info_map,
        dpu_model=dpu_model,
        machine_under_test_dpu=machine_under_test_dpu,
        machine_under_test_predicted_host=machine_under_test_predicted_host,
    )


def collect_ngc_uuids(test_config: TestConfig, site_config: SiteConfig) -> NGCUUIDs:
    """Collect all required UUIDs from NGC for instance creation.
    These objects must be created and present on the cloud before test run.

    Args:
        test_config: The test configuration containing test settings
        site_config: The site configuration containing site information
    Returns:
        NGCUUIDs: Object containing all required UUIDs
    """

    instance_type_name = f"machine-lifecycle-test-{test_config.machine_sku}"
    vpc_name = "machine-lifecycle-test-vpc"
    subnet_name = "machine-lifecycle-test-subnet"
    os_name = "machine-lifecycle-test-os"

    site_uuid = ngc.get_site_uuid(site_config.site.name)
    instance_type_uuid = ngc.get_instance_type_uuid(instance_type_name, site_uuid)
    vpc_uuid = ngc.get_vpc_uuid(vpc_name, site_uuid)
    subnet_uuid = ngc.get_subnet_uuid(subnet_name, vpc_uuid)
    os_uuid = ngc.get_operating_system_uuid(os_name)

    print(f"{site_uuid=}")
    print(f"{instance_type_name=}")
    print(f"{instance_type_uuid=}")
    print(f"{vpc_name=}")
    print(f"{vpc_uuid=}")
    print(f"{subnet_name=}")
    print(f"{subnet_uuid=}")
    print(f"{os_name=}")
    print(f"{os_uuid=}")

    return NGCUUIDs(
        site_uuid=site_uuid,
        instance_type_uuid=instance_type_uuid,
        vpc_uuid=vpc_uuid,
        subnet_uuid=subnet_uuid,
        os_uuid=os_uuid,
    )


def verify_initial_machine_state(test_config: TestConfig) -> None:
    """Check that the machine is in a good state before starting the test.

    Args:
        test_config: The test configuration containing machine information
    """
    print("Checking machine is 'Ready'")
    if not admin_cli.check_machine_ready(test_config.machine_under_test):
        _error_and_exit("Machine is not Ready!")

    print("Checking machine is not in maintenance mode")
    if not admin_cli.check_machine_not_in_maintenance(test_config.machine_under_test):
        _error_and_exit("Machine is in maintenance mode!")

    print("Checking machine is not receiving a DPU FW update")
    if not admin_cli.check_machine_not_updating(test_config.machine_under_test):
        _error_and_exit("Machine is receiving a DPU FW update!")


def _download_firmware_files(test_config: TestConfig) -> FirmwarePaths:
    """Download all required firmware files for a DPU downgrade.

    Args:
        test_config: The test configuration containing firmware version information
    Returns:
        FirmwarePaths: Object containing local paths to the downloaded firmware files
    """
    # Get firmware versions and URLs from config
    selected_fw = SUPPORTED_FW_VERSIONS_FOR_DOWNGRADE[test_config.fw_downgrade_version]
    bmc_fw_url = selected_fw["BMC_FW_URL"]
    cec_fw_url = selected_fw["CEC_FW_URL"]
    bfb_url = selected_fw["BFB_URL"]

    bmc_fw_path = os.path.join(os.getcwd(), bmc_fw_url.split("/")[-1])
    cec_fw_path = os.path.join(os.getcwd(), cec_fw_url.split("/")[-1])
    bfb_path = os.path.join(os.getcwd(), bfb_url.split("/")[-1])

    # Download BMC firmware if necessary
    if not os.path.isfile(bmc_fw_path):
        try:
            utils.download_firmware_file(bmc_fw_url)
        except Exception as e:
            _error_and_exit(f"BMC firmware failed to download: {e}")

    # Download CEC firmware if necessary
    if not os.path.isfile(cec_fw_path):
        try:
            utils.download_firmware_file(cec_fw_url)
        except Exception as e:
            _error_and_exit(f"BMC CEC firmware failed to download: {e}")

    # Download BFB if necessary
    if not os.path.isfile(bfb_path):
        try:
            utils.download_firmware_file(bfb_url)
        except Exception as e:
            _error_and_exit(f"BFB failed to download: {e}")

    return FirmwarePaths(bmc_fw_path=bmc_fw_path, cec_fw_path=cec_fw_path, bfb_path=bfb_path)


def _power_cycle_host_and_wait(
    machine_info: MachineInfo, site_config: SiteConfig, wait_for_redfish: bool = True
) -> None:
    """Power-cycle the host and wait for services to be available again.

    Args:
        machine_info: Information about the machine under test
        site_config: The site configuration containing credentials
        wait_for_redfish: Whether to wait for redfish endpoints to be available
    """
    try:
        utils.power_cycle_host(
            machine_info.vendor,
            machine_info.host_bmc_ip,
            machine_info.host_bmc_username,
            site_config.host_bmc_password,
        )
        time.sleep(10)
        [
            network.wait_for_host_port(
                machine_info.dpu_info_map[dpu_id]["oob_ip"], 22, max_retries=20
            )
            for dpu_id in machine_info.dpu_ids
        ]
        if wait_for_redfish:
            [
                network.wait_for_redfish_endpoint(
                    hostname=machine_info.dpu_info_map[dpu_id]["bmc_ip"]
                )
                for dpu_id in machine_info.dpu_ids
            ]
    except Exception as e:
        _error_and_exit(f"Failed to power-cycle host {machine_info.host_bmc_ip}: {e}")


def _apply_bmc_cec_firmware(
    site_config: SiteConfig, machine_info: MachineInfo, bmc_fw_path: str, cec_fw_path: str
) -> None:
    """Apply BMC and CEC firmware to downgrade the DPU(s).

    Args:
        site_config: The site configuration containing credentials
        machine_info: Information about the machine under test
        bmc_fw_path: Local path to the BMC firmware file
        cec_fw_path: Local path to the CEC firmware file
    """
    # Apply BMC firmware
    for dpu_id in machine_info.dpu_ids:
        print(f"Downgrading BMC firmware of {dpu_id}")
        try:
            utils.apply_dpu_bmc_firmware(
                bmc_fw_path,
                machine_info.dpu_info_map[dpu_id]["bmc_ip"],
                site_config.dpu_bmc_username,
                site_config.dpu_bmc_password,
            )
        except Exception as e:
            _error_and_exit(f"BMC firmware downgrade failed on {dpu_id}: {e}")

    # Apply CEC firmware
    for dpu_id in machine_info.dpu_ids:
        print(f"Downgrading CEC firmware of {dpu_id}")
        try:
            utils.apply_dpu_bmc_firmware(
                cec_fw_path,
                machine_info.dpu_info_map[dpu_id]["bmc_ip"],
                site_config.dpu_bmc_username,
                site_config.dpu_bmc_password,
            )
        except Exception as e:
            _error_and_exit(f"CEC firmware downgrade failed on {dpu_id}: {e}")

    # Power-cycle host after BMC & CEC downgrades
    print(f"Power-cycling host {machine_info.host_bmc_ip} after BMC & CEC downgrades")
    _power_cycle_host_and_wait(machine_info, site_config)


def _apply_bfb_nic_firmware(
    test_config: TestConfig, site_config: SiteConfig, machine_info: MachineInfo, bfb_path: str
) -> None:
    """Apply BFB and NIC firmware to downgrade the DPU(s).

    Args:
        test_config: The test configuration containing firmware version information
        site_config: The site configuration containing credentials
        machine_info: Information about the machine under test
        bfb_path: Local path to the BFB file
    """
    # Get NIC firmware URL from config
    selected_fw = SUPPORTED_FW_VERSIONS_FOR_DOWNGRADE[test_config.fw_downgrade_version]
    nic_fw_url = selected_fw["NIC_FW_URL"]

    # Function to compare version strings
    def version_tuple(v):
        return tuple(map(int, v.split(".")))

    # Ensure rshim is enabled on DPU(s)
    for dpu_id in machine_info.dpu_ids:
        try:
            if version_tuple(test_config.fw_downgrade_version) >= version_tuple("2.5.0"):
                # Use redfish on BMC 23.10+ (i.e. DOCA 2.5.0)
                utils.enable_rshim_on_dpu(
                    machine_info.dpu_info_map[dpu_id]["bmc_ip"],
                    site_config.dpu_bmc_username,
                    site_config.dpu_bmc_password,
                )
            else:
                # Use ipmitool on BMC 23.09 and below
                utils.enable_rshim_on_dpu_ipmi(
                    machine_info.dpu_info_map[dpu_id]["bmc_ip"],
                    site_config.dpu_bmc_username,
                    site_config.dpu_bmc_password,
                )
            time.sleep(10)
        except Exception as e:
            _error_and_exit(f"Failed to enable rshim on DPU {dpu_id}: {e}")

    # Copy BFB file to DPU(s)
    for dpu_id in machine_info.dpu_ids:
        print(f"Downgrading BFB on {dpu_id}")
        try:
            utils.copy_bfb_to_dpu(
                bfb_path,
                machine_info.dpu_info_map[dpu_id]["bmc_ip"],
                site_config.dpu_bmc_username,
                site_config.dpu_bmc_password,
            )
        except Exception as e:
            _error_and_exit(f"Failed to copy BFB to DPU {dpu_id}: {e}")

    print("Sleeping for 5 minutes for BFB install to complete...")
    time.sleep(60 * 5)

    # Downgrade NIC firmware on DPU(s)
    for dpu_id in machine_info.dpu_ids:
        try:
            utils.apply_nic_firmware(
                nic_fw_url,
                machine_info.dpu_info_map[dpu_id]["bmc_ip"],
                site_config.dpu_bmc_username,
                site_config.dpu_bmc_password,
            )
        except Exception as e:
            _error_and_exit(f"Failed to downgrade NIC firmware on DPU {dpu_id}: {e}")

    # Power-cycle host after BFB & NIC downgrade
    print(f"Power-cycling host {machine_info.host_bmc_ip} after BFB & NIC downgrade")
    _power_cycle_host_and_wait(machine_info, site_config)


def _apply_firmware(
    test_config: TestConfig,
    site_config: SiteConfig,
    machine_info: MachineInfo,
    bmc_fw_path: str,
    cec_fw_path: str,
    bfb_path: str,
) -> None:
    """Apply firmware files to downgrade the DPU(s).
    This downgrades the BMC, CEC, BFB and NIC firmware before power-cycling the host

    Args:
        test_config: The test configuration containing firmware version information
        site_config: The site configuration containing credentials
        machine_info: Information about the machine under test
        bmc_fw_path: Local path to the BMC firmware file
        cec_fw_path: Local path to the CEC firmware file
        bfb_path: Local path to the BFB file
    """
    # Put machine into maintenance mode to prevent Forge trying to upgrade it
    print("Putting machine into maintenance mode before firmware downgrade")
    try:
        admin_cli.put_machine_into_maintenance_mode(test_config.machine_under_test)
    except subprocess.CalledProcessError:
        _error_and_exit("Setting maintenance mode pre-downgrade failed")

    # Prevent state machine from attempting to reboot the machine
    print("Setting health-alert on machine to prevent state machine attempting to reboot it")
    try:
        admin_cli.disable_state_machine_intervention(test_config.machine_under_test)
    except subprocess.CalledProcessError:
        _error_and_exit("Setting health-alert pre-downgrade failed")

    _apply_bmc_cec_firmware(site_config, machine_info, bmc_fw_path, cec_fw_path)
    _apply_bfb_nic_firmware(test_config, site_config, machine_info, bfb_path)
    time.sleep(20)  # Workaround for brief 400 error from redfish


def verify_firmware_versions(
    test_config: TestConfig,
    site_config: SiteConfig,
    machine_info: MachineInfo,
    downgraded: bool = False,
) -> None:
    """Verify that firmware versions have been downgraded to expected versions.

    Args:
        test_config: The test configuration containing firmware version information
        site_config: The site configuration containing credentials
        machine_info: Information about the machine under test
        downgraded: Whether to validate against the downgraded or auto-upgraded versions from test config
    """
    # Get firmware versions from config
    if downgraded:
        expected_fw = SUPPORTED_FW_VERSIONS_FOR_DOWNGRADE[test_config.fw_downgrade_version]
        expected_bmc_version = expected_fw["BMC_VERSION"]
        expected_cec_version = expected_fw["CEC_VERSION"]
        expected_bfb_version = expected_fw["BFB_VERSION"]
        expected_nic_version = expected_fw["NIC_VERSION"]
    else:
        expected_bmc_version = config.BMC_VERSION_UP
        expected_cec_version = config.CEC_VERSION_UP
        expected_bfb_version = config.BFB_VERSION_UP
        expected_nic_version = config.NIC_VERSION_UP

    # Verify BMC & CEC versions
    for dpu_id in machine_info.dpu_ids:
        try:
            bmc_version = utils.get_reported_bmc_version(
                machine_info.dpu_info_map[dpu_id]["bmc_ip"],
                site_config.dpu_bmc_username,
                site_config.dpu_bmc_password,
            )
            if expected_bmc_version not in bmc_version:
                _error_and_exit(
                    f"DPU {dpu_id} reports BMC version {bmc_version}, expected {expected_bmc_version}"
                )
            print(f"Confirmed BMC at {expected_bmc_version} on {dpu_id}")

            cec_version = utils.get_reported_cec_version(
                machine_info.dpu_info_map[dpu_id]["bmc_ip"],
                site_config.dpu_bmc_username,
                site_config.dpu_bmc_password,
            )
            if expected_cec_version not in cec_version:
                _error_and_exit(
                    f"DPU {dpu_id} reports CEC version {cec_version}, expected {expected_cec_version}"
                )
            print(f"Confirmed CEC at {expected_cec_version} on {dpu_id}")
        except Exception as e:
            _error_and_exit(f"Failed to confirm BMC & CEC versions on {dpu_id}: {e}")

    # Verify BFB & NIC versions
    for dpu_id in machine_info.dpu_ids:
        try:
            bfb_version = utils.get_reported_bfb_version(
                machine_info.dpu_info_map[dpu_id]["bmc_ip"],
                site_config.dpu_bmc_username,
                site_config.dpu_bmc_password,
            )
            if expected_bfb_version not in bfb_version:
                _error_and_exit(
                    f"DPU {dpu_id} reports BFB version {bfb_version}, expected {expected_bfb_version}"
                )
            print(f"Confirmed BFB at {expected_bfb_version} on {dpu_id}")

            nic_version = utils.get_reported_nic_version(
                machine_info.dpu_info_map[dpu_id]["bmc_ip"],
                site_config.dpu_bmc_username,
                site_config.dpu_bmc_password,
            )
            if expected_nic_version not in nic_version:
                _error_and_exit(
                    f"DPU {dpu_id} reports NIC version {nic_version}, expected {expected_nic_version}"
                )
            print(f"Confirmed NIC at {expected_nic_version} on {dpu_id}")
        except Exception as e:
            _error_and_exit(f"Failed to confirm BFB & NIC versions on {dpu_id}: {e}")


def perform_firmware_downgrade(
    test_config: TestConfig, site_config: SiteConfig, machine_info: MachineInfo
) -> None:
    """Perform DPU firmware downgrade, verify the versions, and remove the files after.

    Args:
        test_config: The test configuration containing firmware version information
        site_config: The site configuration containing credentials
        machine_info: Information about the machine under test
    """
    firmware_paths = _download_firmware_files(test_config)

    _apply_firmware(
        test_config,
        site_config,
        machine_info,
        firmware_paths.bmc_fw_path,
        firmware_paths.cec_fw_path,
        firmware_paths.bfb_path,
    )

    # Clean up local firmware files
    files_to_remove = [
        firmware_paths.bmc_fw_path,
        firmware_paths.cec_fw_path,
        firmware_paths.bfb_path,
    ]
    for file in files_to_remove:
        try:
            os.remove(file)
        except FileNotFoundError as e:
            print(f"File not found for removal: {e}")
        except Exception as e:
            _error_and_exit(f"Failed to remove firmware file: {e}")


def _factory_reset_dpu(
    test_config: TestConfig, site_config: SiteConfig, machine_info: MachineInfo
) -> None:
    """Perform factory reset on DPU(s).

    Args:
        test_config: The test configuration containing test settings
        site_config: The site configuration containing credentials
        machine_info: Information about the machine under test
    """
    i = 1
    for dpu_id in machine_info.dpu_ids:
        bmc_ip = machine_info.dpu_info_map[dpu_id]["bmc_ip"]
        print(f"Resetting BIOS settings on DPU{i}")
        if test_config.dpu_fw_downgrade:
            # Different endpoint in redfish v1.9.0
            url = f"https://{bmc_ip}/redfish/v1/Systems/Bluefield/Bios/Actions/Bios.ResetBios"
            print(f"Executing redfish request. \nURL: {url}")
            response = requests.post(
                url, auth=(site_config.dpu_bmc_username, site_config.dpu_bmc_password), verify=False
            )
        else:
            url = f"https://{bmc_ip}/redfish/v1/Systems/Bluefield/Bios/Settings"
            data = {"Attributes": {"ResetEfiVars": True}}
            print(f"Executing redfish request. \nPayload: {data} \nURL: {url}")
            response = requests.patch(
                url,
                json=data,
                auth=(site_config.dpu_bmc_username, site_config.dpu_bmc_password),
                verify=False,
            )
        if response.status_code != 200:
            print(response.text)
            _error_and_exit(
                f"Failed to reset BIOS settings on DPU{i}. Status code: {response.status_code}",
                set_maintenance=True,
                machine_id=test_config.machine_under_test,
            )
        else:
            print(f"Resetting BIOS settings on DPU{i} was successful.")
            time.sleep(5)
        print(f"Restarting DPU{i} BMC")
        admin_cli.restart_bmc(dpu_id)
        time.sleep(5)
        network.wait_for_redfish_endpoint(hostname=machine_info.dpu_info_map[dpu_id]["bmc_ip"])
        time.sleep(30)

        print(f"Factory-resetting DPU{i} BMC")
        admin_cli.factory_reset_bmc(
            machine_info.dpu_info_map[dpu_id]["bmc_ip"],
            site_config.dpu_bmc_username,
            site_config.dpu_bmc_password,
        )
        time.sleep(5)
        network.wait_for_redfish_endpoint(hostname=machine_info.dpu_info_map[dpu_id]["bmc_ip"])

        i += 1


def _factory_reset_host(
    test_config: TestConfig, site_config: SiteConfig, machine_info: MachineInfo
) -> None:
    """Perform factory reset on host.

    Args:
        test_config: The test configuration containing test settings
        site_config: The site configuration containing credentials
        machine_info: Information about the machine under test
    """
    if machine_info.vendor == "lenovo":
        print("Resetting BIOS settings on the Lenovo host")
        url = f"https://{machine_info.host_bmc_ip}/redfish/v1/Systems/1/Bios/Actions/Bios.ResetBios"
        data = {"ResetType": "default"}
        print(f"Executing redfish request. \nData: {data} \nURL: {url}")
        response = requests.post(
            url,
            json=data,
            auth=(machine_info.host_bmc_username, site_config.host_bmc_password),
            verify=False,
        )
        if response.status_code == 202:
            # Success, wait for redfish task to complete
            task_id = response.json()["Id"]
            attempts = 0
            max_attempts = 30
            print(f"Waiting for async redfish task {task_id} to complete")
            while attempts < max_attempts:
                url = f"https://{machine_info.host_bmc_ip}/redfish/v1/TaskService/Tasks/{task_id}"
                response = requests.get(
                    url,
                    auth=(machine_info.host_bmc_username, site_config.host_bmc_password),
                    verify=False,
                )
                if response.status_code != 200:
                    print(response.text)
                    _error_and_exit(
                        f"Failed to get redfish task status. Status code: {response.status_code}",
                        set_maintenance=True,
                        machine_id=test_config.machine_under_test,
                    )
                if response.json()["TaskState"] == "Completed":
                    print("Redfish task completed.")
                    break
                else:
                    print("Redfish task not yet completed, state %s" % response.json()["TaskState"])
                    attempts += 1
                    time.sleep(10)
            else:
                _error_and_exit(
                    "Redfish task did not complete in 5 minutes",
                    set_maintenance=True,
                    machine_id=test_config.machine_under_test,
                )
        else:
            print(response.text)
            _error_and_exit(
                f"Failed to reset BIOS settings on the Lenovo host. Status code: {response.status_code}",
                set_maintenance=True,
                machine_id=test_config.machine_under_test,
            )

        print("Removing the BIOS password from the Lenovo host")
        admin_cli.clear_host_bios_password(test_config.machine_under_test)
        print("Restarting the host")
        admin_cli.restart_machine(test_config.machine_under_test)
        time.sleep(10)
        network.wait_for_redfish_endpoint(hostname=machine_info.host_bmc_ip)

        print("Factory-resetting the Lenovo BMC")
        admin_cli.factory_reset_bmc(
            machine_info.host_bmc_ip, machine_info.host_bmc_username, site_config.host_bmc_password
        )
        time.sleep(5)
        network.wait_for_redfish_endpoint(hostname=machine_info.host_bmc_ip)
    else:
        # Dell
        print("Factory-resetting Dell machine")
        factory_reset_methods = DellFactoryResetMethods(
            machine_info.host_bmc_ip, machine_info.host_bmc_username, site_config.host_bmc_password
        )
        print("Unlocking iDRAC")
        # Unlock iDRAC if needed
        factory_reset_methods.unlock_idrac()

        print("Resetting BIOS settings to default on the Dell host")
        # Reset bios/uefi to defaults and reboot the server
        try:
            factory_reset_methods.reset_bios()
        except Exception as e:
            _error_and_exit(f"Error occurred during BIOS reset: {e}")

        factory_reset_methods.reboot_server()

        print("Dell BIOS/UEFI settings reset complete. Waiting for server to reboot...")
        # We can't check for redfish endpoint so waiting 5 minutes
        time.sleep(300)
        network.wait_for_redfish_endpoint(hostname=machine_info.host_bmc_ip)

        # Disable host header check
        factory_reset_methods.disable_host_header_check()

        # Factory reset the BMC (iDRAC)
        print("Factory-resetting the iDRAC")
        try:
            factory_reset_methods.factory_reset_bmc(level="ResetAllWithRootDefaults")
        except Exception as e:
            _error_and_exit(f"Error occurred during iDRAC factory reset: {e}")

        print("Dell BMC factory-reset complete. Waiting for BMC to reboot...")
        time.sleep(30)
        network.wait_for_redfish_endpoint(hostname=machine_info.host_bmc_ip)

        with ForgeVaultClient(path="forge/machine-lifecycle-test") as vault_client:
            default_dell_bmc_password: str = vault_client.get_default_dell_bmc_password()

        print("Changing BMC password to match expected machines password")
        expected_machines = admin_cli.get_expected_machines(machine_info.host_bmc_mac)
        if expected_machines["bmc_password"] != default_dell_bmc_password:
            factory_reset_methods = DellFactoryResetMethods(
                machine_info.host_bmc_ip, machine_info.host_bmc_username, default_dell_bmc_password
            )
            factory_reset_methods.change_bmc_password(expected_machines["bmc_password"])


def perform_factory_reset(
    test_config: TestConfig, site_config: SiteConfig, machine_info: MachineInfo
) -> None:
    """Perform a factory-reset on the DPU(s) and host.

    Args:
        test_config: The test configuration containing test settings
        site_config: The site configuration containing credentials
        machine_info: Information about the machine under test
    """
    _factory_reset_dpu(test_config, site_config, machine_info)
    _factory_reset_host(test_config, site_config, machine_info)

    # Confirm DPU password is reset before force-deleting, so we won't hit AvoidLockout error
    i = 1
    for dpu_id in machine_info.dpu_ids:
        time.sleep(5)
        print(f"Checking DPU{i} BMC password is reset")
        try:
            network.check_dpu_password_reset(
                machine_info.dpu_info_map[dpu_id]["bmc_ip"], max_retries=5
            )
        except Exception as e:
            _error_and_exit(
                f"Password reset check failed on DPU{i}: {e}",
                set_maintenance=True,
                machine_id=test_config.machine_under_test,
            )
        i += 1

    # Ensure the machine is still "Ready" after the factory-reset
    print(f"Checking {test_config.machine_under_test} is still Ready")
    if not admin_cli.check_machine_ready(test_config.machine_under_test):
        _error_and_exit(
            f"Machine {test_config.machine_under_test} is no longer Ready!",
            set_maintenance=True,
            machine_id=test_config.machine_under_test,
        )


def force_delete_and_await_reingestion(
    test_config: TestConfig, site_config: SiteConfig, machine_info: MachineInfo
) -> None:
    """Perform force delete operation and wait for machine to reach Ready state.

    Args:
        test_config: The test configuration containing test settings
        site_config: The site configuration containing credentials
        machine_info: Information about the machine under test
    """
    # Force-delete machine from Forge database
    print(f"Force-deleting machine {test_config.machine_under_test}")
    if not test_config.skip_factory_reset:
        admin_cli.force_delete_machine(test_config.machine_under_test, delete_creds=True)
    else:
        admin_cli.force_delete_machine(test_config.machine_under_test, delete_creds=False)

    # Machine ingestion
    # If there is a failure anywhere here, attempt to put the machine into maintenance mode
    # for investigation (this will prevent future runs affecting the machine).
    try:
        # Wait for HostInitializing state
        print("Waiting for carbide to report DPU in any 'HostInitializing' state")
        hostinit_timeout = (
            config.WAIT_FOR_HOSTINIT_AFTER_DOWNGRADE
            if test_config.dpu_fw_downgrade
            else config.WAIT_FOR_HOSTINIT
        )
        admin_cli.wait_for_machine_hostinitializing(
            machine_info.machine_under_test_dpu, timeout=hostinit_timeout
        )

        # Wait for 'Ready' state
        print("Waiting for carbide to report DPU 'Ready'")
        admin_cli.wait_for_machine_ready(
            machine_info.machine_under_test_dpu, timeout=config.WAIT_FOR_READY
        )

        # After the DPU state gets to Ready, allow for the possibility that Forge tries to upgrade the DPU FW.
        # Then confirm the managed host and Cloud machine states both show Ready too.
        print(
            "Sleeping for 2 minutes to allow Forge to possibly grab the machine for a DPU FW upgrade..."
        )
        time.sleep(60 * 2)

        print("Waiting for the machine not to be receiving a DPU FW update from Forge...")
        admin_cli.wait_for_machine_not_updating(test_config.machine_under_test, timeout=60 * 90)

        print("Checking that carbide reports the managed host Ready")
        admin_cli.check_machine_ready(test_config.machine_under_test)

        print("Waiting for the Cloud to also report machine Ready")
        ngc.wait_for_machine_ready(
            test_config.machine_under_test, site_config.site, timeout=60 * 10
        )

    except Exception as e:
        print(e.args[0], file=sys.stderr)
        print(
            "Exception while waiting for machine Ready, putting machine into maintenance mode",
            file=sys.stderr,
        )
        # We have to use managed host ID to do this, not DPU ID, but this may not exist
        # in the database yet depending on where the process got to before it failed.
        try:
            _error_and_exit(str(e), set_maintenance=True, machine_id=test_config.machine_under_test)
        except Exception:
            print(
                "Setting maintenance mode failed, trying again using predicted host id",
                file=sys.stderr,
            )
            _error_and_exit(
                str(e),
                set_maintenance=True,
                machine_id=machine_info.machine_under_test_predicted_host,
            )


def create_instance_and_verify(
    test_config: TestConfig, site_config: SiteConfig, ngc_uuids: NGCUUIDs
) -> str | None:
    """Create an instance, wait for it to be ready, and verify SSH access.

    Args:
        test_config: The test configuration containing test settings
        site_config: The site configuration containing site information
        ngc_uuids: Object containing all required NGC UUIDs
    Returns:
        str: The instance UUID
    """
    # Get SSH key out of corp vault (vault kv get -mount=secrets forge/machine-lifecycle-test)
    with ForgeVaultClient(path="forge/machine-lifecycle-test") as vault_client:
        private_key: str = vault_client.get_ssh_private_key()
    with io.StringIO(initial_value=private_key) as ssh_private_key_file:
        ssh_private_key = paramiko.ed25519key.Ed25519Key.from_private_key(ssh_private_key_file)

    try:
        # Create instance
        print("Creating an instance on the machine")
        instance_name = f"machine-lifecycle-test-instance-{test_config.expected_dpu_count}-{str(uuid.uuid4())[:8]}"
        instance = ngc.create_instance(
            instance_name,
            ngc_uuids.instance_type_uuid,
            ngc_uuids.subnet_uuid,
            ngc_uuids.os_uuid,
            ngc_uuids.vpc_uuid,
        )
        instance_uuid = instance["id"]
        print(f"Instance {instance_uuid} creation success")

        print("Waiting for carbide to report machine 'Assigned/Ready'")
        admin_cli.wait_for_machine_assigned_ready(test_config.machine_under_test, timeout=60 * 10)

        # With phone-home enabled, Forge Cloud will only report the instance 'Ready' once it's booted and reported back
        print("Waiting for Forge Cloud to report instance 'Ready' to the tenant")
        ngc.wait_for_instance_ready(
            instance_uuid, site_config.site, timeout=config.WAIT_FOR_INSTANCE
        )

        instance_ip_address = ngc.wait_for_instance_ip(
            instance_uuid, ngc_uuids.subnet_uuid, timeout=60 * 20
        )

        print(f"Testing SSH connection to the instance {instance_uuid} at {instance_ip_address}")
        network.wait_for_host_port(instance_ip_address, 22, max_retries=40)
        with paramiko.SSHClient() as ssh_client:
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(
                instance_ip_address, pkey=ssh_private_key, username="machine-lifecycle-test-user"
            )

            command = "uptime"
            print(
                f"Executing command: {command} on instance {instance_uuid} at {instance_ip_address}"
            )
            i, o, e = ssh_client.exec_command(command)
            stdout = o.readlines()
            stderr = e.readlines()
            exit_status = o.channel.recv_exit_status()
            print(f"{command!r} stdout: {stdout}")
            print(f"{command!r} stderr: {stderr}")
            if exit_status != 0:
                print(f"{command!r} exited with status {exit_status}", file=sys.stderr)

        return instance_uuid

    except Exception as e:
        print(e.args[0], file=sys.stderr)
        _error_and_exit(
            "Exception during instance creation/verification",
            set_maintenance=True,
            machine_id=test_config.machine_under_test,
        )
        return None


def delete_instance_and_verify(
    test_config: TestConfig, ngc_uuids: NGCUUIDs, instance_uuid: str
) -> None:
    """Delete the instance and wait for deprovisioning to complete.

    Args:
        test_config: The test configuration containing test settings
        ngc_uuids: Object containing all required NGC UUIDs
        instance_uuid: UUID of the instance to delete
    """
    try:
        print("Deleting the instance")
        ngc.delete_instance(instance_uuid)

        print("Waiting for the instance to be deleted...")
        ngc.wait_for_vpc_to_not_contain_instance(
            ngc_uuids.site_uuid, ngc_uuids.vpc_uuid, instance_uuid, timeout=60 * 90
        )

        print("Waiting for carbide to report the managed host 'Ready'...")
        admin_cli.wait_for_machine_ready(test_config.machine_under_test, timeout=60 * 120)
    except Exception as e:
        print(e.args[0], file=sys.stderr)
        _error_and_exit(
            "Exception during instance deletion/deprovisioning",
            set_maintenance=True,
            machine_id=test_config.machine_under_test,
        )


if __name__ == "__main__":
    main()
