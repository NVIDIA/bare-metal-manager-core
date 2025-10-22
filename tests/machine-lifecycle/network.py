"""Things we might want to do with a Forge Instance."""

import datetime
import socket
import time

import requests


def wait_for_host_port(
    hostname: str, port: int, max_retries: int = 20, sleep_time: float = 30
) -> None:
    """Wait until `port` on `hostname` is connectable.

    Sleep for `sleep_time` in between attempts, up to `max_retries`.
    :raises TimeoutError: if not successful within `max_retries`
    """
    _time_print(
        f"Attempting to connect to {hostname} port {port} up to {max_retries} times with {sleep_time=}"
    )
    retry_count = 0
    while retry_count < max_retries:
        # Check if the port is up on the host: 0 for yes 1 for no
        if _test_host_port(hostname, port) == 0:
            _time_print(
                f"Successfully connected to {hostname} port {port} on attempt {retry_count}"
            )
            return
        retry_count += 1
        _time_print(f"Unable to connect to {hostname} port {port} after {retry_count} attempts")
        time.sleep(sleep_time)

    raise TimeoutError(_time_print(f"Unable to contact {hostname} port {port}"))


def wait_for_redfish_endpoint(
    hostname: str, max_retries: int = 20, sleep_time: float = 30, consecutive_successes: int = 3
) -> None:
    """Wait until Redfish API endpoint is running consistently on a given BMC with `hostname`

    Sleep for `sleep_time` in between attempts, up to `max_retries`.
    Requires `consecutive_successes` successful responses to ensure the BMC is stable.
    :raises TimeoutError: if not successful within `max_retries`
    """
    _time_print(
        f"Attempting to connect to Redfish API on {hostname} up to {max_retries} times with "
        f"{sleep_time=}, requiring {consecutive_successes} consecutive successes"
    )
    url = f"https://{hostname}/redfish/v1/"
    retry_count = 0
    success_count = 0

    while retry_count < max_retries:
        try:
            response = requests.get(url, timeout=10, verify=False)
            response.raise_for_status()
            data = response.json()
            if not data.get("Vendor"):
                raise KeyError("The 'Vendor' field is missing or empty.")

            success_count += 1
            _time_print(
                f"Successful response from Redfish API on {hostname} "
                f"({success_count}/{consecutive_successes})"
            )

            if success_count >= consecutive_successes:
                _time_print(
                    f"Redfish API on {hostname} is consistently responding after "
                    f"{consecutive_successes} consecutive successes"
                )
                return

            # Brief pause between consecutive checks
            time.sleep(5)

        except (
            requests.exceptions.RequestException,
            requests.exceptions.JSONDecodeError,
            KeyError,
        ) as e:
            _time_print(
                f"Invalid response from {hostname}: {e} \nRetrying in {sleep_time} seconds..."
            )
            success_count = 0  # Reset success count on any failure
            retry_count += 1
            time.sleep(sleep_time)

    raise TimeoutError(
        _time_print(f"No consistent response from {hostname} within the time limit.")
    )


def check_dpu_password_reset(bmc_ip: str, max_retries: int = 5) -> None:
    """Check that the DPU BMC password is reset to default with retry mechanism.

    This function performs multiple checks to ensure the BMC is consistently in the
    password-reset state. Sleeping 20 seconds between attempts.

    Args:
        bmc_ip: IP address of the BMC to check
        max_retries: Number of times to attempt to connect to BMC (default: 5)
    """
    required_successes = 3  # Require multiple consecutive successes for stability
    consecutive_successes = 0
    sleep_time = 20
    url = f"https://{bmc_ip}/redfish/v1/UpdateService"  # Any auth'd endpoint will do
    _time_print(f"Checking DPU password reset on BMC {bmc_ip} with {max_retries} retries")

    for attempt in range(max_retries):
        try:
            # Check for 403 with text PasswordChangeRequired.
            # This indicates successful password reset
            response = requests.get(url, auth=("root", "0penBmc"), timeout=10, verify=False)
            password_change_required = "PasswordChangeRequired" in response.text

            if password_change_required and response.status_code == 403:
                consecutive_successes += 1
                _time_print(
                    f"Password reset check {consecutive_successes}/{required_successes} passed on "
                    f"BMC {bmc_ip}"
                )

                if consecutive_successes >= required_successes:
                    _time_print(
                        f"Password reset successfully verified with {consecutive_successes} "
                        f"consecutive checks on BMC {bmc_ip}"
                    )
                    return

                # Pause between consecutive checks
                time.sleep(sleep_time)
            else:
                consecutive_successes = 0  # Reset on any failure
                _time_print(
                    f"Password reset check failed on BMC {bmc_ip} "
                    f"(attempt {attempt + 1}/{max_retries}). "
                    f"Status: {response.status_code}, PasswordChangeRequired: "
                    f"{password_change_required}. "
                    f"Expected: HTTP 403 with PasswordChangeRequired present in response"
                )
                if attempt < max_retries - 1:  # Don't sleep on last attempt
                    time.sleep(sleep_time)

        except requests.exceptions.RequestException as e:
            consecutive_successes = 0  # Reset on any failure
            _time_print(
                f"Network error checking BMC {bmc_ip} (attempt {attempt + 1}/{max_retries}): {e}"
            )
            if attempt < max_retries - 1:
                time.sleep(sleep_time)

    # If we get here, all retries failed
    raise Exception(
        _time_print(
            f"Password reset verification failed on BMC {bmc_ip} after {max_retries} attempts"
        )
    )


def _time_print(message) -> str:
    string = f"{datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d %H:%M:%S')}: {message}"
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
