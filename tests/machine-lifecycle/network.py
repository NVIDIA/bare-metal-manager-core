"""Things we might want to do with a Forge Instance."""

import socket
import time


def wait_for_host_port(hostname: str, port: int, max_retries: int = 20, sleep_time: float = 30) -> None:
    """Wait until `port` on `hostname` is connectable.

    Sleep for `sleep_time` in between attempts, up to `max_retries`.
    :raises TimeoutError: if not successful within `max_retries`
    """
    print(f"Attempting to connect to {hostname} port {port} up to {max_retries} times with {sleep_time=}")
    retry_count = 0
    while retry_count < max_retries:
        # Check if the port is up on the host: 0 for yes 1 for no
        if _test_host_port(hostname, port) == 0:
            return
        retry_count += 1
        print(f"Unable to connect to {hostname} port {port} after {retry_count} attempts")
        time.sleep(sleep_time)
    else:
        raise TimeoutError(f"Unable to contact {hostname} port {port}")


def _test_host_port(host: str, port: int) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(20)
    try:
        result = sock.connect_ex((host, port))
        return result
    finally:
        sock.close()
