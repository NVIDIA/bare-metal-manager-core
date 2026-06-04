# DHCP & PXE Boot — Discovery and Troubleshooting Guide

This document covers how to discover, monitor, and troubleshoot the full
DHCP → PXE → Scout OS → carbide-api boot flow for BMC nodes and DPU NICs.

---

## 1. Network Layout (Quick Reference)

NICo serves DHCP on the **10G BMC OOB network** (VLAN 101) for both Host BMC and DPU BMC NICs.


| Network            | Switch              | Subnet          | DHCP Pool | carbide-dhcp VIP | carbide-pxe VIP |
| ------------------ | ------------------- | --------------- | --------- | ---------------- | --------------- |
| Host BMC OOB (10G) | 10G Switch VLAN 101 | `172.16.0.0/24` | `.20–.60` | `172.16.0.85`    | `172.16.0.86`   |
| DPU BMC OOB (10G)  | 10G Switch VLAN 101 | `172.16.0.0/24` | `.20–.60` | `172.16.0.85`    | `172.16.0.86`   |


---

## 2. Boot Flow (End-to-End)

```
BMC powers on
  │
  ├─► DHCP Discover (VLAN 101, broadcast)
  │     └─► 10G Switch relays to 172.16.0.85 (carbide-dhcp) via ip helper-address
  │
  ├─► carbide-dhcp receives Discover
  │     └─► gRPC call → carbide-api
  │           └─► Allocates IP from 172.16.0.20–.60
  │
  ├─► DHCP Offer
  │     ├─ Assigned IP (e.g. 172.16.0.25)
  │     └─ next-server = 172.16.0.86 (carbide-pxe)
  │
  ├─► DHCP Request / ACK
  │
  ├─► Host PXE boots
  │     └─► Downloads iPXE from carbide-pxe :80
  │
  ├─► Scout OS boots
  │     └─► Scout agent → mTLS/gRPC → carbide-api:443
  │           └─► Reports full hardware inventory
  │
  ├─► DPU BMC gets DHCP on VLAN 101 → site-explorer Redfish → DPU Agent installed
  │
  └─► State machine transitions:
        Discovering → Inventoried → Validated → Ready
```

---

## 3. Commands to Discover and Monitor DHCP

### 3a. Kubernetes service and pod status

```bash
# Check carbide-dhcp and carbide-pxe LoadBalancer VIPs are assigned
kubectl get svc -n forge-system | grep -E 'carbide-dhcp|carbide-pxe'
# Expect:
#   carbide-dhcp  LoadBalancer  172.16.0.85  67/UDP  ← handles both BMC and DPU networks
#   carbide-pxe   LoadBalancer  172.16.0.86  80/TCP

# Check pods are Running
kubectl get pods -n forge-system | grep -E 'carbide-dhcp|carbide-pxe'
```

### 3b. Live DHCP log (main stream — shows Discover/Offer/Request/ACK)

```bash
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-dhcp -f
# Expect: DHCPDISCOVER → DHCPOFFER → DHCPREQUEST → DHCPACK
```

### 3c. Live PXE log

```bash
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-pxe -f
```

### 3d. Watch machine discovery state transitions

```bash
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-api -f \
  | grep -i "state\|machine\|discover\|scout"
```

### 3e. List machines and their current state via CLI

```bash
export CARBIDE_API="https://172.16.0.89:443"
alias ncli="$HOME/carbide-admin-cli -c $CARBIDE_API"

ncli machine list
```

### 3f. Verify DHCP VIP is reachable at L2 from the k8s node

```bash
# Replace ens4 with the interface on the 172.16.0.0/24 network
arping -I ens4 172.16.0.85   # carbide-dhcp VIP
arping -I ens4 172.16.0.86   # carbide-pxe VIP
```

### 3g. Verify MetalLB is announcing VIPs

```bash
kubectl get pods -n metallb-system
kubectl logs -n metallb-system -l component=speaker | grep -i "172.16.0.8"

# Check IPAddressPool and L2Advertisement
kubectl get ipaddresspool -n metallb-system -o yaml
kubectl get l2advertisement -n metallb-system -o yaml
```

### 3h. Check DHCP endpoints (pod backing the service is healthy)

```bash
kubectl get endpoints -n forge-system carbide-dhcp
```

### 3i. Verify kea-dhcp4 binaries are present inside the running pod

```bash
kubectl exec -n forge-system \
  $(kubectl get pod -n forge-system -l app.kubernetes.io/name=carbide-dhcp -o name | head -1) \
  -- ls -lh /sbin/kea-dhcp4 \
             /opt/carbide/forge-dhcp-server \
             /usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so
```

### 3j. Sniff DHCP traffic on the host (packet-level confirmation)

```bash
# Run on nico-cp-1, replace ens4 with the OOB interface
sudo tcpdump -i ens4 -n port 67 or port 68 -v

# Filter only from a specific BMC MAC
sudo tcpdump -i ens4 -n 'ether host AA:BB:CC:DD:EE:01 and (port 67 or port 68)' -v
```

### 3k. Simulate a DHCP Discover from the k8s node (no BMC needed)

```bash
# Install dhcping if not present
sudo apt-get install -y dhcping

# Send a discover to the carbide-dhcp VIP
sudo dhcping -s 172.16.0.85 -i ens4 -v
```

### 3l. Check iPXE template configuration

```bash
ncli ipxe-template show
```

### 3m. Confirm switch relay config reaches the VIP

```bash
# From the k8s node, simulate what the switch would send (UDP 67 → 172.16.0.85)
# nmap can probe UDP 67 reachability
nmap -sU -p 67 172.16.0.85
```

---

## 4. Switch DHCP Relay Configuration Reference

The **10G Switch** (VLAN 101) needs a DHCP relay pointing to `172.16.0.85`.
Both Host BMC and DPU BMC NICs are on this network and receive DHCP from carbide-dhcp.

### Cumulus Linux

```
auto vlan101
iface vlan101
  address 172.16.0.1/24
  vlan-id 101
  dhcp-relay 172.16.0.85
```

### Arista EOS

```
interface Vlan101
  ip address 172.16.0.1/24
  ip helper-address 172.16.0.85
```

### Cisco IOS / NX-OS

```
interface Vlan101
  ip address 172.16.0.1 255.255.255.0
  ip helper-address 172.16.0.85
```

### SONiC

```bash
config interface ip add Vlan101 172.16.0.1/24
# DHCP relay configured via dhcp_relay container targeting 172.16.0.85
```

---

## 5. Troubleshooting Quick Reference


| Symptom                                         | Likely Cause                                                | Fix                                                                             |
| ----------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------- |
| Only `DHCPDISCOVER`, no `DHCPOFFER` in logs     | Switch `ip helper-address` not set, or VIP unreachable      | Check Phase 8 switch config; `arping -I ens4 172.16.0.85` from k8s node         |
| `carbide-dhcp` pod not Running                  | Runtime base missing kea packages                           | Rebuild `Dockerfile.runtime-base` with `--no-cache --build-arg SQUID_PROXY=...` |
| `/sbin/kea-dhcp4: not found` in pod logs        | Stale `carbide-runtime-base` built before kea was installed | Wipe BuildKit cache, rebuild runtime-base, redeploy                             |
| `libdhcp.so: No such file or directory`         | `carbide-dhcp` cdylib build failed silently                 | `docker rmi build-container-localdev` then `devspace build --force-build`       |
| `PXE 404`                                       | BMC MAC not in `expected_machines.json`                     | `ncli em list`, re-run Phase 9c                                                 |
| `PXE connection refused`                        | `carbide-pxe` pod not Running or VIP unassigned             | `kubectl get pods,svc -n forge-system`                                          |
| `arping` works, `ping` fails with ICMP Redirect | Missing `172.16.0.0/24` route on source host                | `sudo ip route add 172.16.0.0/24 dev <iface>`                                   |
| MetalLB VIP never assigned                      | No `L2Advertisement` or wrong pool range                    | `kubectl get ipaddresspool,l2advertisement -n metallb-system`                   |
| Machine stuck in `Discovering`                  | Scout OS not booting / carbide-api unreachable              | Check `carbide-pxe` logs; verify mTLS certs; `kubectl logs carbide-api`         |


---

## 6. Full Boot Verification Checklist

Run these in order after deploying NICo and powering on a bare-metal node:

```bash
# 1. MetalLB VIPs assigned
kubectl get svc -n forge-system | grep LoadBalancer

# 2. Pods running
kubectl get pods -n forge-system
kubectl get pods -n metallb-system

# 3. VIPs reachable at L2
arping -I ens4 172.16.0.85
arping -I ens4 172.16.0.86

# 4. Switch relay confirmed (packet sniff)
sudo tcpdump -i ens4 -n port 67 or port 68 -v &

# 5. Power on a machine and watch DHCP
kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-dhcp -f &

# 6. Watch PXE download
kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-pxe -f &

# 7. Watch state machine
kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-api -f \
  | grep -i "state\|discover\|scout" &

# 8. Confirm machine appears
ncli machine list
```

