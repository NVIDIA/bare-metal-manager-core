import os
import time

import paramiko
from scp import SCPClient
import pexpect
import requests
from requests import Response
from requests.auth import HTTPBasicAuth


def download_firmware_file(url: str) -> None:
    """Downloads a firmware file from the given URL and saves it to the current working directory.

    :raises requests.exceptions.RequestException: if an HTTP error occurs
    """
    print(f"Downloading file: {url}")
    file_name = url.split("/")[-1]
    save_path = os.path.join(os.getcwd(), file_name)
    try:
        response = requests.get(url, stream=True, verify=False)
        response.raise_for_status()
        with open(save_path, "wb") as file:
            for chunk in response.iter_content(chunk_size=1024):
                file.write(chunk)
        print(f"Firmware file downloaded successfully: {save_path}")
    except requests.exceptions.RequestException as e:
        print(f"An HTTP error occurred when downloading the file: {e}")
        raise


def apply_dpu_bmc_firmware(bmc_fw_path: str, dpu_bmc_ip: str, dpu_bmc_username: str, dpu_bmc_password: str) -> None:
    """Uploads a firmware file to a BMC via redfish, and waits for the task to complete.

    This can be used for both BMC and CEC firmware files.
    :raises FileNotFoundError: if the file does not exist
    :raises requests.exceptions.RequestException: if an HTTP error occurs
    :raises TimeoutError: if the task does not complete within 15 minutes
    """
    try:
        response = _upload_fw_to_bmc(bmc_fw_path, dpu_bmc_ip, dpu_bmc_username, dpu_bmc_password)
        task_id = response.json()["Id"]
        if task_id is None or task_id == "null":
            raise ValueError(f"Task was not created for firmware upload to {dpu_bmc_ip}")
        _wait_for_task_complete(task_id, dpu_bmc_ip, dpu_bmc_username, dpu_bmc_password, timeout=60*15)
    except requests.exceptions.RequestException as e:
        raise requests.exceptions.RequestException(f"HTTP request failed: {e}") from e
    except TimeoutError as e:
        raise TimeoutError(f"Task timeout: {e}") from e


def copy_bfb_to_dpu(bfb_path: str, bmc_ip: str, bmc_username: str, bmc_password: str) -> None:
    """Copies a given BFB to /dev/rshim0/boot on the specified BMC."""
    #  TODO: Once we support 24.10, we can transfer BFB via redfish UpdateService endpoint instead of scp
    remote_path="/dev/rshim0/boot"
    if not os.path.exists(bfb_path):
        raise Exception(f"Error: File {bfb_path} does not exist")

    last_progress_time = time.monotonic()

    def progress_callback(filename, size, sent):
        nonlocal last_progress_time
        if size == 0:
            print("Warning: File size is 0, cannot track progress.")
            return
        current_time = time.monotonic()
        if current_time - last_progress_time >= 60:  # Report every minute
            percent = min(100, max(0, (sent / size) * 100))  # Clamp to 0-100
            print(f"Transfer progress: {percent:.1f}%")
            last_progress_time = current_time
    
    try:
        with paramiko.SSHClient() as ssh:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=bmc_ip, port=22, username=bmc_username, password=bmc_password)
            with SCPClient(ssh.get_transport(), socket_timeout=60*10, progress=progress_callback) as scp:
                print(f"Copying {bfb_path} to {bmc_ip}...")
                start_time = time.monotonic()
                try:
                    scp.put(bfb_path, remote_path)
                    elapsed = time.monotonic() - start_time
                    print(f"File successfully transferred to {bmc_ip}:{remote_path} in {elapsed / 60:.2f} minutes")
                except Exception as scp_error:
                    error_msg = str(scp_error)
                    if "truncate: Invalid argument" in error_msg:
                        print("Warning: Paramiko SCP transfer encountered known issue (truncate invalid), continuing..")
                    else:
                        raise Exception(f"Failed to copy BFB to DPU: {error_msg}")
    except Exception as e:
        raise Exception(f"Failed to establish SSH connection or copy BFB to DPU. Error: {e}")


def apply_nic_firmware(fw_url: str, bmc_ip: str, bmc_username: str, bmc_password: str, timeout: int = 60 * 5) -> None:
    """SSH to DPU BMC, connect to rshim console, download NIC firmware binary, unzip it, and install it.

    :param timeout: Maximum time to wait for fw install in seconds (default: 5 mins)
    :raises Exception: If any step fails or times out
    :raises TimeoutError: If the operation times out
    """
    fw_filename = fw_url.split("/")[-1]
    base_fw_filename = fw_filename.replace(".zip", "")
    dpu_user = "ubuntu"
    dpu_password = "ubuntu"
    temporary_dpu_password = "Passw0rd123"
    try:
        print(f"Attempting SSH connection to {bmc_username}@{bmc_ip}")
        ssh = pexpect.spawn(f"ssh -o StrictHostKeyChecking=no {bmc_username}@{bmc_ip}", encoding="utf-8")
        ssh.expect("password:", timeout=20)
        print("Password prompt received, sending password...")
        ssh.sendline(bmc_password)
        ssh.expect(f"{bmc_username}@dpu-bmc:~#", timeout=10)
        print("Shell prompt received, starting microcom session...")

        # Start microcom session
        ssh.sendline("microcom /dev/rshim0/console")
        ssh.sendline("")  # Send return to get login prompt
        print("Waiting for DPU login prompt...")
        ssh.expect("login:", timeout=10)

        # Login sequence
        print("Sending DPU username...")
        ssh.sendline(dpu_user)
        ssh.expect("Password:", timeout=10)
        print("Sending DPU password...")
        ssh.sendline(dpu_password)
        ssh.expect("Current password:")
        print("Password change prompt received, sending current password...")
        ssh.sendline(dpu_password)
        ssh.expect("New password:")
        print("Sending temporary new password...")
        ssh.sendline(temporary_dpu_password)
        ssh.expect("Retype new password:")
        print("Confirming temporary new password...")
        ssh.sendline(temporary_dpu_password)
        ssh.expect(":~\\$", timeout=10)
        print("Ubuntu shell prompt received")

        # Switch password back to default
        print("Changing password back to default")
        ssh.sendline(f"sudo passwd {dpu_user}")
        ssh.expect("New password:")
        print("Sending default password...")
        ssh.sendline(dpu_password)
        ssh.expect("Retype new password:")
        print("Confirming default password...")
        ssh.sendline(dpu_password)
        ssh.expect("password updated successfully")
        
        # Download NIC firmware
        print(f"Downloading NIC firmware from {fw_url}")
        ssh.sendline(f"curl -k -L -O '{fw_url}'")
        ssh.expect(":~\\$", timeout=10)
        print("Download complete")

        # Unzip NIC firmware
        print(f"Unzipping {fw_filename}")
        ssh.sendline(f"unzip {fw_filename}")
        ssh.expect(":~\\$", timeout=15)
        print("Unzip complete")
    
        # Run flint command to install NIC firmware binary
        print(f"Installing NIC firmware {base_fw_filename}")
        ssh.sendline(f"sudo flint -y --device 3:0.0 --image {base_fw_filename} b")
        ssh.expect("run mlxfwreset or reboot machine", timeout=timeout)
        print("Firmware installation complete")
            
        # Exit microcom with Ctrl+X
        ssh.sendcontrol("x")
        ssh.close()
    except pexpect.TIMEOUT as e:
        print(f"Timeout occurred. Last output before timeout: {ssh.before}")
        raise TimeoutError(f"Operation timed out: {str(e)}")
    except pexpect.EOF as e:
        print(f"Connection closed unexpectedly. Last output: {ssh.before}")
        raise Exception(f"SSH connection closed unexpectedly: {str(e)}")
    except Exception as e:
        print(f"Error occurred. Last output: {ssh.before}")
        raise Exception(f"Failed to downgrade NIC firmware via rshim: {str(e)}")


def get_reported_bfb_version(bmc_ip: str, username: str, password: str) -> str:
    """Get the reported BFB version from redfish

    :raises requests.exceptions.RequestException: if an HTTP error occurs
    :raises KeyError: if the 'Vendor' field is missing or empty
    :raises JSONDecodeError: if the response is not valid JSON
    """
    print(f"Getting BFB version from BMC {bmc_ip}")
    url = f"https://{bmc_ip}/redfish/v1/UpdateService/FirmwareInventory/DPU_OS"
    response = requests.get(url, auth=HTTPBasicAuth(username, password), verify=False)
    response.raise_for_status()
    return response.json()["Version"]


def get_reported_nic_version(bmc_ip: str, username: str, password: str) -> str:
    """Get the reported NIC version from redfish

    :raises requests.exceptions.RequestException: if an HTTP error occurs
    :raises KeyError: if the 'Vendor' field is missing or empty
    :raises JSONDecodeError: if the response is not valid JSON
    """
    print(f"Getting NIC version from BMC {bmc_ip}")
    url = f"https://{bmc_ip}/redfish/v1/UpdateService/FirmwareInventory/DPU_NIC"
    response = requests.get(url, auth=HTTPBasicAuth(username, password), verify=False)
    response.raise_for_status()
    return response.json()["Version"]


def get_reported_bmc_version(bmc_ip: str, username: str, password: str) -> str:
    """
    Get the reported BMC firmware version from redfish

    :raises requests.exceptions.RequestException: if an HTTP error occurs
    :raises KeyError: if the 'Vendor' field is missing or empty
    :raises JSONDecodeError: if the response is not valid JSON
    """
    print(f"Getting BMC firmware version from BMC {bmc_ip}")
    url = f"https://{bmc_ip}/redfish/v1/UpdateService/FirmwareInventory/BMC_Firmware"
    response = requests.get(url, auth=HTTPBasicAuth(username, password), verify=False)
    response.raise_for_status()
    return response.json()["Version"]


def get_reported_cec_version(bmc_ip: str, username: str, password: str) -> str:
    """
    Get the reported BMC CEC/ERoT firmware version from redfish

    :raises requests.exceptions.RequestException: if an HTTP error occurs
    :raises KeyError: if the 'Vendor' field is missing or empty
    :raises JSONDecodeError: if the response is not valid JSON
    """
    print(f"Getting CEC firmware version from BMC {bmc_ip}")
    url = f"https://{bmc_ip}/redfish/v1/UpdateService/FirmwareInventory/Bluefield_FW_ERoT"
    response = requests.get(url, auth=HTTPBasicAuth(username, password), verify=False)
    response.raise_for_status()
    return response.json()["Version"]


def power_cycle_host(vendor: str, bmc_ip: str, username: str, password: str) -> None:
    """AC power-cycle a host machine using redfish.

    :raises ValueError: if the vendor is not valid
    :raises requests.exceptions.RequestException: if an HTTP error occurs
    """
    print("Performing AC power-cycle on host via redfish")
    if "Lenovo" in vendor:
        url = f"https://{bmc_ip}/redfish/v1/Systems/1/Actions/Oem/LenovoComputerSystem.SystemReset"
        data = {"ResetType": "ACPowerCycle"}
    elif "Dell" in vendor:
        url = f"https://{bmc_ip}/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"
        data = {"ResetType": "PowerCycle"}
    else:
        raise ValueError(f"Unsupported vendor: {vendor}")
    response = requests.post(url, json=data, auth=HTTPBasicAuth(username, password), verify=False)
    response.raise_for_status()


def enable_rshim_on_dpu(bmc_ip: str, username: str, password: str) -> None:
    """This is a workaround to ensure rshim is enabled on the DPU BMC.

    :raises requests.exceptions.RequestException: if an HTTP error occurs
    """
    print(f"Enabling rshim on DPU BMC {bmc_ip}")
    url = f"https://{bmc_ip}/redfish/v1/Managers/Bluefield_BMC/Oem/Nvidia"
    data = {"BmcRShim": {"BmcRShimEnabled": True}}
    response = requests.patch(url, json=data, auth=HTTPBasicAuth(username, password), verify=False)
    response.raise_for_status()


def _upload_fw_to_bmc(file_path: str, bmc_ip: str, username: str, password: str) -> Response:
    """Uploads a firmware file to a BMC via redfish

    :raises FileNotFoundError: if the file does not exist
    :raises requests.exceptions.RequestException: if an HTTP error occurs
    """
    print(f"Uploading file {file_path} to BMC {bmc_ip}")
    with open(file_path, "rb") as file:
        headers = {"Content-Type": "application/octet-stream"}
        redfish_url = f"https://{bmc_ip}/redfish/v1/UpdateService/update"
        response = requests.post(
            redfish_url,
            headers=headers,
            data=file,
            auth=HTTPBasicAuth(username, password),
            verify=False
        )
        response.raise_for_status()
        print("Firmware file uploaded successfully.")
        return response


def _wait_for_task_complete(
    task_id: str, bmc_ip: str, username: str, password: str, timeout: int = 600, poll_interval: int = 5
) -> None:
    """Wait for a redfish task to complete.

    Default timeout is 10 minutes.
    :raises requests.exceptions.RequestException: if an HTTP request fails.
    :raises TimeoutError: if the task does not complete within the timeout period.
    :raises KeyError: if the task state is missing or empty.
    """
    print(f"Waiting for redfish task {task_id} to complete on BMC {bmc_ip}...")
    url = f"https://{bmc_ip}/redfish/v1/TaskService/Tasks/{task_id}"
    start_time = time.monotonic()
    while True:
        response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=10, verify=False)
        response.raise_for_status()
        task_state = response.json()["TaskState"]
        if task_state == "Completed":
            print(f"Redfish task completed after {time.monotonic() - start_time:.2f} seconds")
            return
        elif task_state != "Running":
            raise Exception(f"Unexpected state '{task_state}' for redfish task {task_id}. Expected 'Running'.")
        time.sleep(poll_interval)
        if time.monotonic() - start_time > timeout:
            raise TimeoutError(f"Timed out after {timeout} seconds waiting for redfish task {task_id} to complete.")
