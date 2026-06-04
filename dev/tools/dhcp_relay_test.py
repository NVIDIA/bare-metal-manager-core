#!/usr/bin/env python3
"""
dhcp_relay_test.py — End-to-end DHCP relay tester for carbide-dhcp.

Simulates a switch relay agent by:
  1. Sending a DHCP Discover with giaddr set (non-zero, so carbide-dhcp accepts it).
  2. Waiting for the DHCP Offer reply via a regular UDP socket on port 67.

Must be run as root (raw UDP port 67 bind requires root).
No extra dependencies — uses only Python stdlib.

Usage:
  sudo python3 dhcp_relay_test.py \\
      --server 172.16.0.85 \\
      --giaddr 172.16.0.121 \\
      --mac    50:6b:8d:a3:05:39

Notes:
  - giaddr should be this host's IP on the 172.16.0.0/24 subnet.
    carbide-api uses it to look up which network segment to allocate from.
  - The OFFER reply is unicast to giaddr:67 (RFC 2131 §4.1). It arrives at
    the kernel UDP socket bound to port 67 normally — no raw socket needed.
  - Missing option [60] / [93] in carbide-dhcp logs are benign during testing.
  - An offered IP of 172.16.0.2 (or similar) with an unknown MAC is normal;
    it means carbide-api allocated from the pool start. Register the MAC in
    expected_machines.json to get a stable/correct lease.
"""

import argparse
import random
import socket
import struct
import sys


# ---------------------------------------------------------------------------
# Packet builder
# ---------------------------------------------------------------------------

def mac_to_bytes(mac_str: str) -> bytes:
    return bytes(int(x, 16) for x in mac_str.split(":"))


def build_dhcp_discover(mac_str: str, giaddr_str: str, xid: int) -> bytes:
    mac    = mac_to_bytes(mac_str)
    giaddr = socket.inet_aton(giaddr_str)

    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,              # op: BOOTREQUEST
        1,              # htype: Ethernet
        6,              # hlen: MAC length
        1,              # hops: relay agent increments this to 1
        xid,
        0,              # secs
        0x8000,         # flags: broadcast
        b"\x00" * 4,   # ciaddr
        b"\x00" * 4,   # yiaddr
        b"\x00" * 4,   # siaddr
        giaddr,         # giaddr — MUST be non-zero for carbide-dhcp to accept
        mac + b"\x00" * 10,  # chaddr padded to 16 bytes
        b"\x00" * 64,  # sname
        b"\x00" * 128, # file
    )

    options = (
        b"\x63\x82\x53\x63"       # DHCP magic cookie
        b"\x35\x01\x01"            # option 53: DHCP Message Type = Discover
        b"\x37\x04\x01\x03\x06\x0f"  # option 55: Parameter Request List
        b"\xff"                    # option 255: End
    )

    return bootp + options


# ---------------------------------------------------------------------------
# Reply parser
# ---------------------------------------------------------------------------

def parse_dhcp_reply(data: bytes) -> dict:
    result = {
        "offered_ip": socket.inet_ntoa(data[16:20]) if len(data) >= 20 else "?",
        "msg_type": None,
        "server_id": None,
        "subnet_mask": None,
        "router": None,
        "dns": None,
        "hostname": None,
        "lease_time": None,
    }
    if len(data) < 240:
        return result

    i = 4  # skip magic cookie
    options = data[240:]
    while i < len(options):
        opt = options[i]
        if opt == 255:
            break
        if opt == 0:
            i += 1
            continue
        if i + 1 >= len(options):
            break
        length = options[i + 1]
        val = options[i + 2: i + 2 + length]
        if opt == 53 and length >= 1:
            result["msg_type"] = val[0]
        elif opt == 54 and length == 4:
            result["server_id"] = socket.inet_ntoa(val)
        elif opt == 1 and length == 4:
            result["subnet_mask"] = socket.inet_ntoa(val)
        elif opt == 3 and length >= 4:
            result["router"] = socket.inet_ntoa(val[:4])
        elif opt == 6 and length >= 4:
            result["dns"] = socket.inet_ntoa(val[:4])
        elif opt == 12:
            result["hostname"] = val.decode(errors="replace")
        elif opt == 51 and length == 4:
            result["lease_time"] = struct.unpack("!I", val)[0]
        i += 2 + length

    return result


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test carbide-dhcp relay end-to-end.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--server",  default="172.16.0.85",       help="carbide-dhcp VIP")
    parser.add_argument("--giaddr",  default="172.16.0.121",      help="This host's IP on 172.16.0.x (relay agent IP)")
    parser.add_argument("--mac",     default="50:6b:8d:a3:05:39", help="Client MAC to test")
    parser.add_argument("--timeout", type=int, default=5,         help="Seconds to wait for OFFER")
    args = parser.parse_args()

    xid = random.randint(1, 0xFFFF_FFFF)
    pkt = build_dhcp_discover(args.mac, args.giaddr, xid)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind(("", 67))
    except PermissionError:
        print("ERROR: must run as root  (sudo python3 dhcp_relay_test.py ...)")
        sys.exit(1)
    sock.settimeout(args.timeout)

    print(f"[TX] DHCP Discover")
    print(f"     client MAC : {args.mac}")
    print(f"     giaddr     : {args.giaddr}  ← relay agent IP (must be in networks.admin subnet)")
    print(f"     server     : {args.server}:67")
    print(f"     xid        : 0x{xid:08x}")
    print()

    sock.sendto(pkt, (args.server, 67))
    print(f"Discover sent. Waiting up to {args.timeout}s for OFFER ...")
    print()

    try:
        while True:
            data, addr = sock.recvfrom(4096)
            # Skip our own outgoing packet reflected back by the socket
            if len(data) < 240:
                continue
            reply = parse_dhcp_reply(data)
            # Filter to our transaction only
            rx_xid = struct.unpack("!I", data[4:8])[0] if len(data) >= 8 else 0
            if rx_xid != xid:
                continue

            type_name = {1: "Discover", 2: "Offer", 3: "Request",
                         5: "ACK", 6: "NAK"}.get(reply["msg_type"], str(reply["msg_type"]))
            print(f"[OK] Got DHCP {type_name} from {addr[0]}")
            print(f"     Offered IP  : {reply['offered_ip']}")
            print(f"     Subnet mask : {reply['subnet_mask'] or '?'}")
            print(f"     Gateway     : {reply['router'] or '?'}")
            print(f"     DNS         : {reply['dns'] or '?'}")
            print(f"     Hostname    : {reply['hostname'] or '?'}")
            print(f"     Lease time  : {reply['lease_time'] or '?'}s")
            print(f"     Server ID   : {reply['server_id'] or '?'}")

            offered = reply["offered_ip"]
            if offered in ("0.0.0.0", "0.0.0.2", "0.0.0.5"):
                print()
                print("  NOTE: Offered IP is a low placeholder — the MAC is not yet registered")
                print("  as an expected machine. The relay and network segment are working.")
                print("  Add the MAC to expected_machines.json to get a stable 172.16.0.x lease.")
            else:
                print()
                print("  carbide-dhcp relay is working correctly end-to-end.")

            sock.close()
            return

    except socket.timeout:
        print("[!!] No OFFER received (timeout).")
        print()
        print("Checklist:")
        print("  1. Did carbide-dhcp receive the Discover?")
        print("     kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-dhcp --tail=20")
        print("     Look for: LOG_CARBIDE_PKT4_RECEIVE ... DHCPDISCOVER")
        print()
        print("  2. carbide-api network segment error?")
        print("     kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-api --tail=20 \\")
        print("       | grep -i 'network segment'")
        print("     → see DEBUG.md § 'DHCP Relay Fails — No network segment defined'")
        print()
        print("  3. Is giaddr reachable from the cluster?")
        print(f"     arping -I eth0 {args.giaddr}   (run on nico-cp-1)")
        print()
        print("  4. OFFER arriving but not visible? Add a direct route to the VIP:")
        print(f"     sudo ip route add {args.server}/32 dev <iface>")
        sock.close()
        sys.exit(1)


if __name__ == "__main__":
    main()
