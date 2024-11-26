"""Things we might want to do with a Forge Instance."""

import datetime
import socket
import time
import requests


def wait_for_host_port(hostname: str, port: int, max_retries: int = 20, sleep_time: float = 30) -> None:
    """Wait until `port` on `hostname` is connectable.

    Sleep for `sleep_time` in between attempts, up to `max_retries`.
    :raises TimeoutError: if not successful within `max_retries`
    """
    _time_print(f"Attempting to connect to {hostname} port {port} up to {max_retries} times with {sleep_time=}")
    retry_count = 0
    while retry_count < max_retries:
        # Check if the port is up on the host: 0 for yes 1 for no
        if _test_host_port(hostname, port) == 0:
            _time_print(f"Successfully connected to {hostname} port {port} on attempt {retry_count}")
            return
        retry_count += 1
        _time_print(f"Unable to connect to {hostname} port {port} after {retry_count} attempts")
        time.sleep(sleep_time)
    else:
        raise TimeoutError(_time_print(f"Unable to contact {hostname} port {port}"))


def wait_for_redfish_endpoint(hostname: str, max_retries: int = 20, sleep_time: float = 30) -> None:
    """Wait until Redfish API endpoint is running on a given BMC with `hostname`

    Sleep for `sleep_time` in between attempts, up to `max_retries`.
    :raises TimeoutError: if not successful within `max_retries`
    """
    _time_print(f"Attempting to connect to Redfish API on {hostname} up to {max_retries} times with {sleep_time=}...")
    url = f"https://{hostname}/redfish/v1/"
    retry_count = 0
    while retry_count < max_retries:
        try:
            response = requests.get(url, timeout=5, verify=False)
            response.raise_for_status()
            _time_print(f"Successful response from Redfish API on {hostname}")
            return
        except requests.exceptions.RequestException:
            _time_print(f"No response from {hostname}. Retrying in {sleep_time} seconds...")
            retry_count += 1
            time.sleep(sleep_time)
    else:
        raise TimeoutError(_time_print(f"No response from {hostname} within the time limit."))


def _time_print(message) -> str:
    string = f"{datetime.datetime.now(datetime.UTC)}: {message}"
    print(string)
    return string


def _test_host_port(host: str, port: int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(20)
    try:
        result = sock.connect_ex((host, port))
        return result
    finally:
        sock.close()
