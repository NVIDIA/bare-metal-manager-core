#!/usr/bin/env python3
"""
Fetch DHCP lease data from Postgres, enrich with chassis serial numbers via Redfish,
and output JSON in all_machines format.

Usage:
  python3 parse_dhcp_psql.py --credentials admin:secret --credentials root:Carbide2026!

Optional:
  --no-redfish   Skip Redfish queries
  --output FILE  Output JSON path (default: expected_machines.json)
"""

import sys
import json
import argparse
import urllib.request
import ssl
import base64
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

_print_lock = threading.Lock()

def _print(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)

# Chassis paths tried in order. First path to return a SerialNumber wins.
REDFISH_CHASSIS_PATHS = [
    "/redfish/v1/Chassis/Chassis_0",      # Standard BMCs (Dell, Supermicro, HPE, etc.)
    "/redfish/v1/Chassis/Bluefield_BMC",  # NVIDIA BlueField DPU BMCs
]

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


def get_redfish_description(ip, timeout=5):
    """Fetch unauthenticated Redfish root to identify device type.
    Returns dict with 'description' and 'vendor' keys, or empty strings if unreachable.
    Falls back to 'Product' field when 'Description' is absent."""
    url = f"https://{ip}/redfish/v1/"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=timeout) as resp:
            data = json.loads(resp.read())
            description = data.get("Description", "").strip() or data.get("Product", "").strip()
            return {
                "description": description,
                "vendor": data.get("Vendor", "").strip(),
            }
    except Exception:
        return {"description": "", "vendor": ""}


def _is_port_open(ip, port=443, timeout=1):
    """Quick TCP check — skip Redfish entirely if port 443 is closed."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _probe_credential(ip, path, username, password, timeout):
    """Single Redfish probe. Returns (serial, status).
    status ∈ {ok, no_serial, 401, 404, connection_refused, timeout, error:<code>}
    """
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    url = f"https://{ip}{path}"
    req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=timeout) as resp:
            data = json.loads(resp.read())
            serial = data.get("SerialNumber", "").strip()
            return (serial, "ok") if serial else ("", "no_serial")
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            try:
                body = json.loads(e.read())
                messages = " ".join(
                    m.get("Message", "") for m in
                    body.get("error", {}).get("@Message.ExtendedInfo", [])
                ).lower()
                if "locked" in messages or "too many" in messages:
                    return "", "locked_out"
            except Exception:
                pass
            return "", str(e.code)
        elif e.code == 404:
            return "", "404"
        return "", f"error:{e.code}"
    except urllib.error.URLError as e:
        return "", "connection_refused" if isinstance(e.reason, ConnectionRefusedError) else "timeout"
    except Exception:
        return "", "timeout"


def get_serial_number(ip, credentials, retries=2, timeout=3):
    """Try each known Redfish chassis path with each credential set sequentially.
    Returns (serial, reason, tried_credentials) tuple.

    Credentials are tried sequentially (not in parallel) to avoid triggering
    BMC account lockouts from burst authentication failures.

    - tried_credentials: list of 'user:pass' strings that got 401 (only on auth failure)
    - Error precedence: connection refused / timeout → immediate return
                        401 all creds              → "HTTP 401 Unauthorized"
                        reachable, no serial        → "Redfish API exists but unable to
                                                       collect the serial number from default paths"
    """
    redfish_reachable = False
    authenticated = False       # True if any credential got HTTP 200
    tried_credentials = []

    for path in REDFISH_CHASSIS_PATHS:
        for username, password in credentials:
            for attempt in range(retries):
                serial, status = _probe_credential(ip, path, username, password, timeout)

                if status == "ok":
                    return serial, None, []

                if status == "connection_refused":
                    return "", "Connection refused", []

                if status == "locked_out":
                    return "", "Account locked out — too many failed authentication attempts", tried_credentials

                if status == "timeout":
                    if attempt < retries - 1:
                        continue  # retry
                    return "", f"Timeout after {retries} attempts", []

                # HTTP response — Redfish is reachable
                redfish_reachable = True

                if status in ("401", "403"):
                    cred_str = f"{username}:{password}"
                    if cred_str not in tried_credentials:
                        tried_credentials.append(cred_str)
                    break  # try next credential

                if status == "404":
                    break  # path doesn't exist — try next path

                if status.startswith("error:"):
                    return "", f"HTTP {status.split(':')[1]}", []

                # no_serial — authenticated successfully but SerialNumber was empty
                authenticated = True
                break  # stop trying credentials for this path; also exits credential loop below

        if authenticated:
            break  # stop trying remaining paths — we already authenticated

    if tried_credentials and not authenticated:
        return "", "HTTP 401/403 Unauthorized", tried_credentials
    if authenticated:
        return "", "Authenticated successfully but SerialNumber not found in Chassis response", []
    if redfish_reachable:
        return "", "Redfish API exists but unable to collect the serial number from default paths", []
    return "", f"Timeout after {retries} attempts", []


def fetch_machine(machine, ip, credentials):
    # #5 — skip Redfish entirely if port 443 is not open
    if not _is_port_open(ip):
        _print(f"  SKIP: {ip} — port 443 closed", file=sys.stderr)
        result = {**machine, "chassis_serial_number": ""}
        result["incomplete_reason"] = "Connection refused"
        result["_credentials_tried"] = []
        result["_redfish_info"] = {"description": "", "vendor": ""}
        return result

    serial, reason, tried = get_serial_number(ip, credentials)
    result = {**machine, "chassis_serial_number": serial}
    mac = machine.get("bmc_mac_address", "")
    if reason:
        redfish_info = get_redfish_description(ip) if ip else {"description": "", "vendor": ""}
        desc = redfish_info["description"]
        vendor = redfish_info["vendor"]
        display = " — ".join(filter(None, [desc, vendor]))
        if "Authenticated successfully" in reason:
            _print(f"  AUTH OK (no serial): {ip} | {mac}{' — ' + display if display else ''}")
        else:
            log_msg = f"  WARNING: {ip} | {mac}: {reason}"
            if tried:
                log_msg += f" (tried: {', '.join(tried)})"
            if display:
                log_msg += f" — {display}"
            _print(log_msg, file=sys.stderr)
        result["incomplete_reason"] = reason
        result["_credentials_tried"] = tried
        result["_redfish_info"] = redfish_info
    else:
        _print(f"  OK: {ip} | {mac} | serial: {serial}")
        result.pop("incomplete_reason", None)
        result.pop("_credentials_tried", None)
        result.pop("_redfish_info", None)
    return result


def upload_to_carbide(output_file, namespace="forge-system"):
    """Copy output_file to the carbide-api pod and run expected-machine replace-all."""
    print("\n  Finding carbide-api pod...", file=sys.stderr)
    result = subprocess.run(
        ["kubectl", "get", "pods", "-n", namespace, "--no-headers",
         "-o", "custom-columns=NAME:.metadata.name"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"  ERROR: kubectl get pods failed: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    pod = next(
        (p for p in result.stdout.splitlines()
         if p.startswith("carbide-api-") and "carbide-api-migrate" not in p),
        None
    )
    if not pod:
        print(f"  ERROR: No carbide-api pod found in namespace {namespace}", file=sys.stderr)
        sys.exit(1)

    print(f"  Uploading {output_file} to {pod}:/tmp/expected_machines.json ...", file=sys.stderr)
    cp = subprocess.run(
        ["kubectl", "cp", output_file, f"{namespace}/{pod}:/tmp/expected_machines.json"],
        capture_output=True, text=True
    )
    if cp.returncode != 0:
        print(f"  ERROR: kubectl cp failed: {cp.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    print(f"  Running expected-machine replace-all ...", file=sys.stderr)
    cli = subprocess.run(
        ["kubectl", "exec", "-n", namespace, pod, "--",
         "/opt/carbide/carbide-admin-cli",
         "-c", "https://carbide-api.forge-system.svc.cluster.local:1079",
         "expected-machine", "replace-all",
         "--filename", "/tmp/expected_machines.json"],
        capture_output=True, text=True
    )
    if cli.stdout.strip():
        print(cli.stdout.strip(), file=sys.stderr)
    if cli.returncode != 0:
        print(f"  ERROR: carbide-admin-cli failed: {cli.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    print(f"  Upload complete.", file=sys.stderr)


def get_leases_from_postgres():
    """Fetch MAC/IP pairs from machine_dhcp_records via kubectl exec + psql."""
    print("  Fetching DHCP records from Postgres...", file=sys.stderr)

    query = "SELECT mac_address, address FROM machine_dhcp_records WHERE address IS NOT NULL;"
    cmd = [
        "kubectl", "exec", "-n", "postgres", "forge-pg-cluster-0", "-c", "postgres",
        "--", "psql", "-U", "postgres", "-d", "forge_system_carbide",
        "-t", "-A", "-F,", "-c", query
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ERROR: Failed to query Postgres: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    leases = {}
    for line in result.stdout.strip().splitlines():
        if not line.strip():
            continue
        mac, ip = line.split(",", 1)
        leases[mac.upper()] = ip

    if not leases:
        print(f"  ERROR: No DHCP records found in database", file=sys.stderr)
        sys.exit(1)

    print(f"  Retrieved {len(leases)} DHCP records", file=sys.stderr)
    return leases


def main():
    parser = argparse.ArgumentParser(description="Parse DHCP leases from Postgres and enrich with Redfish chassis serial numbers.")
    parser.add_argument("--credentials", metavar="USER:PASS", action="append", default=[],
                        help="BMC credentials in user:pass format. Repeatable — each set is tried in order on 401.")
    parser.add_argument("--output", metavar="FILE", default="expected_machines.json", help="Output file path (default: expected_machines.json)")
    parser.add_argument("--no-redfish", action="store_true", help="Skip Redfish calls, leave serial number blank")
    parser.add_argument("--workers", type=int, default=10, help="Parallel Redfish workers (default: 10)")
    parser.add_argument("--upload", action="store_true", help="Upload output to carbide-api pod and run expected-machine replace-all")
    args = parser.parse_args()

    credentials = []
    for c in args.credentials:
        if ":" not in c:
            print(f"ERROR: --credentials must be in user:pass format, got: {c}", file=sys.stderr)
            sys.exit(1)
        user, passwd = c.split(":", 1)
        credentials.append((user, passwd))

    leases = get_leases_from_postgres()

    already_complete = []
    try:
        with open(args.output) as f:
            existing = json.load(f)
        if "all_machines" in existing:
            existing_machines = existing["all_machines"]
            already_complete = [m for m in existing_machines if m.get("successfully_collected_data")]
            incomplete_machines = [m for m in existing_machines if not m.get("successfully_collected_data")]
            # Remap mac_address → bmc_mac_address for internal processing
            for m in already_complete + incomplete_machines:
                if "mac_address" in m and "bmc_mac_address" not in m:
                    m["bmc_mac_address"] = m["mac_address"]
        else:
            # Legacy format with separate expected_machines / incomplete_machines keys
            already_complete = existing.get("expected_machines", [])
            incomplete_machines = existing.get("incomplete_machines", [])

        known_macs = {m["bmc_mac_address"].upper() for m in already_complete + incomplete_machines}
        new_macs = {mac: ip for mac, ip in leases.items() if mac not in known_macs}
        if new_macs:
            print(f"  Found {len(new_macs)} new MAC(s) in DHCP records — adding to query list", file=sys.stderr)

        print(f"  Loaded {len(already_complete)} complete, {len(incomplete_machines)} incomplete entries from {args.output}", file=sys.stderr)
        first_user, first_pass = credentials[0] if credentials else ("", "")
        entries = []
        for m in incomplete_machines:
            mac = m["bmc_mac_address"].upper()
            ip = leases.get(mac)
            entries.append(({**m, "bmc_username": first_user, "bmc_password": first_pass}, ip))

        for mac, ip in new_macs.items():
            entries.append(({"bmc_mac_address": mac, "bmc_username": first_user,
                              "bmc_password": first_pass, "chassis_serial_number": ""}, ip))

    except FileNotFoundError:
        print(f"  No existing file found — scanning all {len(leases)} DHCP records...", file=sys.stderr)
        first_user, first_pass = credentials[0] if credentials else ("", "")
        entries = [
            ({"bmc_mac_address": mac, "bmc_username": first_user,
              "bmc_password": first_pass, "chassis_serial_number": ""},
             ip)
            for mac, ip in leases.items()
        ]

    to_query = [(m, ip) for m, ip in entries if ip]
    skipped = [(m, ip) for m, ip in entries if not ip]

    if already_complete:
        print(f"\n  === Already complete ({len(already_complete)}) — skipping ===", file=sys.stderr)
        for m in already_complete:
            print(f"    SKIP (complete): {m.get('bmc_mac_address','')} | serial: {m.get('chassis_serial_number','')}", file=sys.stderr)

    if skipped:
        print(f"\n  === No IP in DHCP — skipping ({len(skipped)}) ===", file=sys.stderr)
        for m, _ in skipped:
            reason = m.get("incomplete_reason", "No DHCP lease")
            print(f"    SKIP (no IP): {m.get('bmc_mac_address','')} | {reason}", file=sys.stderr)

    print(f"\n  === Queuing {len(to_query)} machine(s) for Redfish query ===\n", file=sys.stderr)

    if args.no_redfish or not credentials:
        new_machines = [{**m, "chassis_serial_number": ""} for m, _ in to_query]
    else:
        _print(f"Querying Redfish for {len(to_query)} machines...", file=sys.stderr)
        new_machines = [None] * len(to_query)

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(fetch_machine, m, ip, credentials): i
                for i, (m, ip) in enumerate(to_query)
            }
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    new_machines[idx] = future.result()
                except Exception:
                    m, _ = to_query[idx]
                    new_machines[idx] = {**m, "chassis_serial_number": ""}

    for m, _ in skipped:
        new_machines.append(m)

    all_machines = already_complete + new_machines

    REQUIRED = ("bmc_mac_address", "bmc_username", "bmc_password", "chassis_serial_number")

    mac_to_machine = {m["bmc_mac_address"].upper(): m for m in all_machines}
    complete_macs = {
        m["bmc_mac_address"].upper() for m in all_machines
        if all(m.get(f) for f in REQUIRED)
    }

    output_machines = []
    for mac, ip in sorted(leases.items(), key=lambda x: tuple(int(o) for o in x[1].split("."))):
        m = mac_to_machine.get(mac, {})
        redfish_info = m.get("_redfish_info", {})
        entry = {
            "successfully_collected_data": mac in complete_macs,
            "ip_address": ip,
            "mac_address": mac,
            "bmc_username": m.get("bmc_username", ""),
            "bmc_password": m.get("bmc_password", ""),
            "chassis_serial_number": m.get("chassis_serial_number", ""),
            "incomplete_reason": m.get("incomplete_reason", ""),
            "vendor": redfish_info.get("vendor", ""),
            "device_description": redfish_info.get("description", ""),
        }
        tried = m.get("_credentials_tried", [])
        if tried:
            entry["credentials_tried"] = tried
        output_machines.append(entry)

    expected_machines = [
        {
            "bmc_mac_address": m["bmc_mac_address"],
            "bmc_username": m["bmc_username"],
            "bmc_password": m["bmc_password"],
            "chassis_serial_number": m["chassis_serial_number"],
        }
        for m in all_machines if all(m.get(f) for f in REQUIRED)
    ]

    with open(args.output, "w") as f:
        json.dump({
            "expected_machines": expected_machines,
            "all_machines": output_machines,
        }, f, indent=2)
    print(f"  Written to {args.output}", file=sys.stderr)

    newly_filled = [m for m in new_machines if m.get("chassis_serial_number")]
    total = len(output_machines)
    complete_count = sum(1 for m in output_machines if m["successfully_collected_data"])
    if newly_filled:
        print(f"\n  Added {len(newly_filled)} new serial number(s):", file=sys.stderr)
        for m in newly_filled:
            print(f"    {m['bmc_mac_address']} -> {m['chassis_serial_number']}", file=sys.stderr)
    else:
        print(f"\n  No new serial numbers added.", file=sys.stderr)
    print(f"  Complete: {complete_count}/{total} | Incomplete: {total - complete_count}/{total}", file=sys.stderr)

    if args.upload:
        upload_to_carbide(args.output)


if __name__ == "__main__":
    main()

