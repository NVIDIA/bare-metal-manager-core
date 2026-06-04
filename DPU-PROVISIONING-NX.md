# DPU Provisioning on NX Nodes — NICo/Carbide Guide

This document describes how to provision a BlueField DPU on an NX node using
NICo (NCX Infra Controller) / Carbide. It covers the full lifecycle: DHCP
discovery → BFB image delivery → DPU agent init → host boot.

> **Troubleshooting / debug walkthrough:** for the chronological story of
> what can go wrong and how each failure was fixed during initial bring-up,
> see [`DPU-PROVISIONING-DEBUG-JOURNEY.md`](DPU-PROVISIONING-DEBUG-JOURNEY.md).
> That doc also documents the production recommendations that emerged from
> the lab journey.

---

## Overview

NICo provisions DPUs via two paths depending on whether DPF (Data Processing
Fabric) is available:

| Path | When used | Key mechanism |
|------|-----------|---------------|
| **BFB via Redfish/rshim** | DPF not available, or BMC supports rshim | `copy-bfb-to-dpu-rshim` CLI command or automatic state machine |
| **DPF operator** | DPF enabled at site, BMC supports BFB install | Carbide registers DPU with DPF; DPF handles internal provisioning |

Both paths go through the same state machine in `ManagedHostState` /
`DpuDiscoveringState` / `DpuInitState`.

---

## Network Architecture — Segments, DPU Interactions, Traffic Direction

This section describes the L2/L3 network segments NICo configures at a site,
which interfaces on the DPU/host attach to each one, and how each segment is
classified in data-center traffic terms (north–south vs. east–west). It is the
mental model to keep when reading the rest of this guide; everything in
`Prerequisites`, `Step 4`, `Step 6` (BFB install) and the DNS / `unbound`
troubleshooting sections is an instance of this picture.

### 1. Segment taxonomy in NICo

NICo's site config (`[networks.*]` in `values.base.yaml` /
`carbideApiSiteConfig`) declares L3 segments. Each segment has a `type`
that controls **what NICo does with it**, not just its name:

| `type` | NICo enum | Purpose | Who lives here |
|--------|-----------|---------|----------------|
| `underlay` | `NetworkSegmentType::Underlay` | **OOB / discovery fabric.** site-explorer scans this for BMCs. Carries DHCP/Redfish/BFB-download traffic from BMCs. | Host BMC NICs, DPU BMC NICs, NICo control-plane VIPs (`carbide-*-external`) |
| `admin` | `NetworkSegmentType::Admin` | **Post-provisioning host inband management.** Used by `create_host_machine_dpu_interface_proactively` to allocate the DPU host inband interface. | DPU `oob_net0` / host inband NIC after the DPU agent comes up |
| `host-inband` | `NetworkSegmentType::HostInband` | Variant of `admin` for non-DPU hosts (treated as tenant-like for IP allocation purposes). | Non-DPU bare-metal hosts |
| `tenant` | `NetworkSegmentType::Tenant` | **Workload / overlay** segment. Tenant VPC traffic terminated on the DPU (VXLAN-encapsulated on the underlay). | Tenant VMs / pods behind the DPU |

> **Critical:** `admin` and `underlay` are **not interchangeable** even though
> the names suggest they might be. The `admin`-typed `[networks.admin]` block
> in earlier examples was a misconfiguration — see
> [`DPU-PROVISIONING-DEBUG-JOURNEY.md § Symptom 1.1`](DPU-PROVISIONING-DEBUG-JOURNEY.md).
> Site-explorer only scans segments where `segment_type = Underlay`; managed
> host creation only allocates from segments where `segment_type = Admin` /
> `HostInband`. The two must be **separate prefixes** with **different
> `type`s**.

### 2. Concrete segments in this lab

`dev/deployment/devspace/values.base.yaml` defines:

```toml
[networks.admin]            # name is cosmetic, type is what matters
type          = "underlay"  # → OOB / BMC discovery fabric (VLAN 101)
prefix        = "172.16.0.0/24"
gateway       = "172.16.0.1"
mtu           = 1500
reserve_first = 20          # .0–.19 reserved for static (gateway, VIPs, VMs)

[networks.host-inband]      # post-provisioning DPU host inband
type          = "admin"     # → allocator for the DPU host inband interface
prefix        = "172.16.10.0/24"
gateway       = "172.16.10.1"
mtu           = 9000        # jumbo — VXLAN headroom for tenant overlay
reserve_first = 20
```

So in the running site:

| Segment | CIDR | VLAN | MTU | NICo type | Role |
|---------|------|------|-----|-----------|------|
| **OOB / ADMIN fabric** | `172.16.0.0/24` | 101 | 1500 | `underlay` | BMC DHCP + Redfish + PXE + BFB download + NICo VIPs + `.forge` DNS |
| **Host inband** | `172.16.10.0/24` | (separate, 100G) | 9000 | `admin` | DPU `oob_net0` post-provisioning, agent ↔ `carbide-api`, tenant overlay underlay |
| **Tenant overlay** | per-VPC (VXLAN VNI from `pools.vni`) | n/a (encapsulated) | logical | `tenant` | VM/pod traffic; VTEPs are the DPUs on `host-inband` |

### 3. Where the DPU plugs into each segment

A BlueField DPU on an NX node has several network interfaces; each one lives
on a different segment of the picture above:

| DPU interface | Connected to | Segment | When it's used |
|---------------|--------------|---------|----------------|
| **DPU BMC NIC** (1G/10G) | 10G switch, VLAN 101 | OOB / ADMIN underlay | From **power-on**. Gets DHCP from `carbide-dhcp`, exposes Redfish, receives BFB image via `SimpleUpdate`. |
| **DPU host BMC rshim** (over PCIe to Host BMC) | n/a (PCIe sideband) | n/a — sideband to Host BMC | Backup BFB-push path: `copy-bfb-to-dpu-rshim` reaches the DPU **through the Host BMC's** Redfish/SSH (Host BMC is on the OOB underlay). |
| **DPU `oob_net0`** (ARM-OS-facing 1G mgmt NIC) | 10G switch on a separate VLAN | host-inband (`admin`) | After the BFB boots: `forge-scout` / `forge-dpu-agent` register with `carbide-api` over this path. |
| **DPU `p0` / `p1`** (100G NIC physical ports) | 100G fabric / TOR | underlay for tenant VXLAN | After the DPU agent is up. VTEP termination for tenant overlay. |
| **DPU `pf0hpf` / VFs** (host-side PFs/VFs exposed to host x86) | Internal to host (PCIe) | tenant overlay (egress via `p0`/`p1`) | After `HostInit`. Host workload NICs — what the host OS / VMs / pods see. |

Two things the DPU does that are easy to miss:

- During provisioning the **DPU's BMC NIC** and the **Host BMC NIC** both sit
  on the **same VLAN 101 / `172.16.0.0/24` underlay**, and they both DHCP
  from the **same `carbide-dhcp` VIP** (`172.16.0.85`) via the 10G switch's
  `ip helper-address` relay. There is no separate BMC network for the DPU.
- The DPU `oob_net0` lives on a **different** segment (`172.16.10.0/24`,
  `host-inband`) that the BMC never touches. This is what `forge-dpu-agent`
  uses to call `carbide-api` after the BFB OS boots — explicitly **not** the
  BMC NIC. Mixing these up is the most common cause of
  `WaitingForNetworkConfig` getting stuck (see the troubleshooting section
  below).

### 4. North–south vs. east–west during provisioning

In data-center terms:

- **North–south (N/S)** = traffic crossing the data-center perimeter or
  between an out-of-band / management plane and an in-band workload plane.
- **East–west (E/W)** = traffic between two workloads (or two
  same-plane nodes) inside the same fabric — overlay-to-overlay, VM-to-VM,
  rack-to-rack.

For NICo / DPU provisioning, all the traffic involved is **management-plane
N/S traffic**. Nothing in steps 1–8 is tenant data-plane east-west traffic:

| Phase | Traffic | Direction | Why it's N/S |
|-------|---------|-----------|--------------|
| DHCP Discover from DPU BMC → `carbide-dhcp` (`172.16.0.85`) | UDP/67 unicast (relayed by 10G switch with `giaddr`) | **N/S — OOB mgmt → controller** | BMC (management plane) reaches into a controller VIP that fronts a tenant-isolated control service. |
| Redfish `SimpleUpdate` from `carbide-api` → DPU BMC | HTTPS/443 (mTLS) on the OOB underlay | **N/S — controller → OOB mgmt** | Controller VIP issues a management RPC to a BMC. |
| BFB image pull from DPU BMC → `carbide-pxe` (`172.16.0.86`) via `carbide-pxe.forge` | HTTP/80 (large, multi-GB) on the OOB underlay | **N/S — OOB mgmt ← controller** | Boot-artifact fetch from a controller-fronted artifact store. |
| DNS query from DPU BMC → `unbound` (`172.16.0.91`) for `carbide-pxe.forge` | UDP/53 on the OOB underlay | **N/S — OOB mgmt → controller** | Name resolution against the infra resolver. |
| `forge-scout` / `forge-dpu-agent` from DPU `oob_net0` → `carbide-api` (`172.16.0.89`) | gRPC over mTLS/443 on host-inband segment | **N/S — DPU mgmt-plane → controller** | DPU agent reports inventory and pulls config from the controller. |
| Host BIOS PXE / iPXE → `carbide-pxe` | HTTP/TFTP on the OOB underlay | **N/S — Host mgmt → controller** | Same boot-artifact fetch pattern as the BFB. |

The first piece of **east–west, in-band** traffic only appears **after**
`HostInit/Ready`:

- Tenant workloads on the host → DPU `pf0hpf` → DPU **encapsulates in VXLAN
  on the tenant overlay** → DPU `p0/p1` → 100G fabric → peer DPU `p0/p1`
  → peer host. That is the only fully east–west, data-plane path in the
  picture, and **NICo does not carry that traffic** — it just bootstraps the
  DPU so that path can exist.

The Carbide control plane itself runs east-west **inside** the Kubernetes
cluster (pod-to-pod gRPC between `carbide-api`, `carbide-dhcp`,
`carbide-pxe`, `unbound`, Postgres, etc.), but this is cluster-internal
service mesh traffic that never leaves the cluster network — irrelevant from
the DPU's perspective.

### 5. Where `unbound` sits in this picture

`unbound` is **only** relevant to the OOB/underlay segment. It exists because:

- The DPU BMC's Redfish `SimpleUpdate` requires a hostname (`carbide-pxe.forge`),
  not an IP. The hostname is hardcoded in
  `crates/api/src/state_controller/machine/handler.rs` and embedded in
  compiled DPU agent binaries (`crates/agent/src/main_loop.rs`).
- The OOB segment has no other authoritative resolver for the `.forge` zone.
  `carbide-dns` (`172.16.0.87` / `.88`) is a **different** service — it serves
  tenant/VPC DNS records via the NICo API and is **not** authoritative for
  `.forge`. Pointing a BMC at it returns NXDOMAIN for `carbide-pxe.forge`.

So the data flow during BFB install is:

```
       OOB / underlay segment  (VLAN 101, 172.16.0.0/24, MTU 1500)
       ────────────────────────────────────────────────────────────
DPU BMC ──(1)── DHCP (giaddr-relayed by 10G switch) ──► carbide-dhcp VIP 172.16.0.85
        ◄──(2)── OFFER w/ option 6: DNS = 172.16.0.91 (unbound)
        ──(3)── DNS query  "carbide-pxe.forge"  A?    ──► unbound      VIP 172.16.0.91
        ◄──(4)── DNS reply  172.16.0.86 (carbide-pxe VIP)
        ──(5)── HTTP GET /public/blobs/.../forge.bfb  ──► carbide-pxe  VIP 172.16.0.86
        ◄──(6)── 2 GB BFB stream
        ──(7)── (after BFB install + reboot) Redfish status ◄── carbide-api 172.16.0.89

       host-inband segment  (172.16.10.0/24, MTU 9000)
       ────────────────────────────────────────────────
DPU oob_net0 ──(8)── gRPC mTLS forge-scout → carbide-api VIP 172.16.0.89
             ◄──(9)── network_config, agent upgrade policy, etc.
```

All seven OOB-segment hops above are **north–south OOB-mgmt ↔ controller**
traffic. The unbound VIP (`172.16.0.91`) is what makes the **(3)/(4)** lookup
succeed; without it, the whole BFB install in **(5)/(6)** fails with
`TransferFailed: Unknown Host` (see
[`§ TransferFailed — BMC cannot download BFB`](#transferfailed--bmc-cannot-download-bfb)).

The **(8)/(9)** path is also N/S, but on a **completely different segment**
(host-inband, MTU 9000) than the BMC-side traffic. This is by design — the
DPU agent's call-home path must not depend on the BMC OOB network being up
once provisioning is complete, and the host-inband segment is jumbo-framed
to leave headroom for VXLAN overlay encapsulation that will run over the
same physical link in the data-plane phase.

### 6. Segment-to-component cheat sheet

```
                    ┌──────────────────────────────────────┐
                    │  OOB / ADMIN underlay (VLAN 101)     │
                    │  172.16.0.0/24, MTU 1500             │
                    │                                      │
   Host BMC ────────┤                                      │
   DPU  BMC ────────┤ carbide-dhcp   .85                   │
                    │ carbide-pxe    .86                   │
                    │ carbide-dns    .87/.88               │
                    │ carbide-api    .89                   │
                    │ unbound        .91  (.forge zone)    │
                    │ ntp            .80                   │
                    └──────────────────────────────────────┘
                                   │
                       (DPU finishes BFB install + reboots)
                                   │
                                   ▼
                    ┌──────────────────────────────────────┐
                    │  host-inband (admin) segment         │
                    │  172.16.10.0/24, MTU 9000            │
                    │                                      │
   DPU oob_net0 ────┤ forge-scout / forge-dpu-agent        │
                    │   └── gRPC mTLS ──► carbide-api      │
                    │       (over the OOB-side VIP .89,    │
                    │        routed via host-inband GW)    │
                    └──────────────────────────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────────────┐
                    │  tenant overlay  (VXLAN, per-VPC VNI)│
                    │                                      │
   DPU pf0hpf  ─────┤ Host workload NIC                    │
   DPU p0/p1   ─────┤ VTEP egress to 100G fabric           │
                    │   (East–West tenant traffic only —   │
                    │    NICo bootstraps but does not      │
                    │    carry this traffic)               │
                    └──────────────────────────────────────┘
```

---

## Prerequisites

Before powering on an NX node, verify **all** of the following:

### 1. NICo services running and VIPs assigned

```bash
kubectl get pods -n forge-system
kubectl get svc -n forge-system | grep LoadBalancer
```

Expected VIPs:

| Service | VIP | Port | Purpose |
|---------|-----|------|---------|
| `carbide-dhcp-external` | `172.16.0.85` | UDP 67 | Host BMC + DPU BMC DHCP (10G / VLAN 101) |
| `carbide-pxe-external` | `172.16.0.86` | TCP 80 | PXE / HTTP boot |
| `carbide-api-external` | `172.16.0.89` | TCP 443 | Scout agent + CLI |

If any show `<pending>`, fix MetalLB first — see
[`DEBUG.md § MetalLB VIPs Pending`](DEBUG.md#metallb-vips-pending).

### 2. carbide-dhcp relay verified end-to-end

carbide-dhcp must be reachable at L2 and able to respond to relayed DHCP requests.
Run this from any host with a `172.16.0.x` IP (e.g. `nico-cp-1` or `nutanixcollector`):

```bash
# Verify L2 reachability
arping -I eth0 -c 3 172.16.0.85

# Verify relay end-to-end (stdlib only, no pip needed)
# Replace giaddr with this host's own 172.16.0.x IP
sudo python3 dev/tools/dhcp_relay_test.py \
    --server 172.16.0.85 \
    --giaddr 172.16.0.121 \
    --mac    50:6b:8d:a3:05:39
```

Expected result:
```
[[TX] DHCP Discover
     client MAC : 50:6b:8d:e3:19:f2
     giaddr     : 172.16.0.121  ← relay agent IP (must be in networks.admin subnet)
     server     : 172.16.0.85:67
     xid        : 0xb6b7e17a

Discover sent. Waiting up to 5s for OFFER ...

[OK] Got DHCP None from 172.16.0.81
     Offered IP  : 172.16.0.20
     Subnet mask : ?
     Gateway     : ?
     DNS         : ?
     Hostname    : ?
     Lease time  : ?s
     Server ID   : ?

  carbide-dhcp relay is working correctly end-to-end.
```

If this fails, see [`DEBUG.md § DHCP Relay Fails`](DEBUG.md#dhcp-relay-fails--no-network-segment-defined-for-relay-address).

### 3. 10G switch relay configured

The 10G switch VLAN 101 interface must have `ip helper-address 172.16.0.85` set.
Without this, BMC DHCP broadcasts never reach carbide-dhcp.

```
# Verify on the switch:
show running-config interface vlan 101
# Must contain: ip helper-address 172.16.0.85
```

### 4. DPU BMC OOB connectivity

The DPU BMC NIC is on the **10G / VLAN 101** network along with the Host BMC. It receives
a DHCP lease from carbide-dhcp via the same 10G Switch relay (`ip helper-address 172.16.0.85`).

Verify reachability once the DPU BMC has its DHCP lease:

```bash
ping <dpu-bmc-ip>
curl -sk https://<dpu-bmc-ip>/redfish/v1 | python3 -m json.tool | head -20
```

### 5. CLI configured

```bash
export CARBIDE_API="https://172.16.0.89:443"
alias ncli="$HOME/carbide-admin-cli -c $CARBIDE_API"
ncli machine list   # should return without TLS error
```

If you get a TLS error, see [`DEBUG.md § CLI TLS Certificate Mismatch`](DEBUG.md#cli-tls-certificate-mismatch).

### 6. BFB image available

```bash
ls -lh /root/*.bfb
# e.g. /root/bf3-dpu.bfb  ~2GB
```

Download from NVIDIA NGC or your internal artifact store if not present.

---

## Step 1 — Register Expected Machines

Carbide's site explorer needs to know what to look for. Each entry maps a BMC
MAC to expected chassis serial.

```bash
cat > expected_machines.json <<'EOF'
{
  "expected_machines": [
    {
      "bmc_mac_address": "AA:BB:CC:DD:EE:01",
      "bmc_username": "root",
      "bmc_password": "<bmc-factory-password>",
      "chassis_serial_number": "SN-NX-001"
    }
  ]
}
EOF

ncli em replace-all --filename expected_machines.json
ncli em list   # verify
```

---

## Step 2 — Set Site Credentials

```bash
ncli credential add-bmc --kind=site-wide-root --password='<new-bmc-password>'
ncli host generate-host-uefi-password
ncli credential add-uefi --kind=host --password='<uefi-password>'
```

---

## Step 3 — Approve TPM Trust (lab/wildcard)

```bash
ncli mb site trusted-machine approve \* persist --pcr-registers="0,3,5,6"
```

---

## Step 4 — Power On the NX Node

Power on the NX node. The DPU BMC NIC sends a DHCP Discover on VLAN 101.

### What happens automatically:

```
DPU BMC NIC powers on
  │
  ├─► DPU BMC NIC gets IP on 172.16.0.0/24 via carbide-dhcp (VLAN 101)
  │     (same 10G Switch relay as Host BMC)
  │
  ├─► Scout OS boots on DPU (BFB installed via Redfish/rshim)
  │     └─► Scout agent → mTLS/gRPC → carbide-api:443
  │           └─► Reports DPU hardware inventory (model, PCI info, Redfish caps)
  │
  └─► carbide-api state machine begins: DpuDiscovering
```

---

## Step 5 — Monitor DPU Discovery State

```bash
# Watch DHCP (single instance handles both BMC and DPU networks)
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-dhcp -f

# Watch PXE downloads
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-pxe -f

# Watch carbide-api state machine transitions
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-api -f \
  | grep -i "dpu\|state\|discover\|bfb\|scout"

# List all DPU machines and their current state
ncli dpu status

# Show a specific machine's state
ncli machine list
```

### DPU Discovery State Progression

Carbide drives through these internal states (visible in `ncli dpu status`
and `carbide-api` logs):

```
DpuDiscovering/Initializing
  └─► Configuring          (Redfish: configure DPU management network)
      └─► EnableRshim      (enable rshim interface for BFB upload)
          └─► SetUefiHttpBoot
              └─► RebootAllDPUS
                  └─► [EnableSecureBoot | DisableSecureBoot]
                      └─► ──► DPUInit/InstallDpuOs
```

---

## Step 6 — BFB Image Installation

### Path A: Automatic (state machine drives it)

Once `DpuDiscovering` completes, Carbide transitions to `DPUInit` and
automatically installs the BFB image via Redfish. Monitor:

```bash
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-api -f \
  | grep -i "bfb\|installdpuos\|InstallingBFB\|WaitForInstallComplete"
```

State progression during BFB install:

```
DPUInit/InstallDpuOs/InstallingBFB
  └─► DPUInit/InstallDpuOs/WaitForInstallComplete (polls task_id)
      └─► DPUInit/InstallDpuOs/Completed
          └─► DPUInit/Init
              └─► DPUInit/WaitingForPlatformPowercycle
                  └─► DPUInit/WaitingForPlatformConfiguration
                      └─► DPUInit/PollingBiosSetup
                          └─► DPUInit/WaitingForNetworkConfig
                              └─► HostInit → Ready
```

### Path B: Manual BFB push via CLI (recovery / debug)

If the automatic path fails or you want to force a BFB re-image:

**Option 1 — Via carbide-api (recommended, uses existing credentials):**
```bash
# carbide-api orchestrates the rshim copy via the site explorer
ncli site-explorer copy-bfb-to-dpu-rshim \
  --address <DPU-BMC-IP> \
  --mac <DPU-BMC-MAC> \
  --host-bmc-ip <HOST-BMC-IP> \
  --pre-copy-powercycle

# Track progress
ncli site-explorer get-report endpoint <DPU-BMC-IP>
```

**Option 2 — Direct SSH to BMC rshim (bypass carbide-api):**
```bash
# BF3 detection is automatic; uses longer timeout for BF2
ncli ssh copy-bfb \
  --bmc-ip-address <DPU-BMC-IP> \
  --bmc-username root \
  --bmc-password '<password>' \
  --bfb-path /root/bf3-dpu.bfb
```

### Path C: DPF operator (if DPF enabled at site)

When DPF is enabled, Carbide delegates provisioning to the DPF operator:

```bash
# State will show DPUInit/DpfStates/Provisioning → WaitingForReady → DeviceReady
ncli dpu status

# Watch DPF operator
kubectl logs -n dpf-system -l app=dpf-operator -f
```

Carbide's DPF states:
```
DPUInit/DpfStates/Provisioning
  └─► DPUInit/DpfStates/WaitingForReady  (polls DPF CRDs)
      └─► DPUInit/DpfStates/DeviceReady  (all DPUs ready)
          └─► HostInit → Ready
```

---

## Step 7 — Host Boot Sequence

**The host cannot boot until the DPU OS is fully initialized.**

Once `DPUInit` completes, Carbide transitions to `HostInit`:

```
DPUInit/WaitingForPlatformPowercycle (powers off/on host)
  └─► DPUInit/WaitingForPlatformConfiguration
      └─► DPUInit/PollingBiosSetup
          └─► DPUInit/WaitingForNetworkConfig
              └─► HostInit/Init
                  └─► HostInit/EnableIpmiOverLan
                      └─► HostInit/WaitingForPlatformConfiguration (BIOS)
                          └─► HostInit/PollingBiosSetup
                              └─► HostInit/SetBootOrder
                                  └─► HostInit/WaitingForDiscovery
                                      └─► HostInit/Discovered
                                          └─► Ready
```

Monitor:
```bash
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-api -f \
  | grep -i "hostinit\|HostInit\|Ready\|SetBootOrder"

ncli machine list
```

---

## Step 8 — Verify DPU Agent

After the node reaches `Ready`, verify the DPU agent is healthy:

```bash
# DPU agent versions
ncli dpu versions

# DPU network information
ncli dpu network

# DPU agent upgrade policy
ncli dpu agent-upgrade-policy

# DPA (DPU Accelerator) interface details
ncli dpa show <machine-id>
```

---

## Reprovision an Existing DPU

If a DPU needs to be re-imaged after initial provisioning:

```bash
# Trigger reprovisioning for a specific DPU
ncli dpu reprovision set --id <DPU-MACHINE-ID>

# With firmware update
ncli dpu reprovision set --id <DPU-MACHINE-ID> --update-firmware

# List DPUs pending reprovisioning
ncli dpu reprovision list

# Clear reprovisioning flag (cancel)
ncli dpu reprovision clear --id <DPU-MACHINE-ID>

# Restart a stalled reprovision
ncli dpu reprovision restart --id <DPU-MACHINE-ID>
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| DPU BMC has no IP / Scout agent not connecting | DPU BMC not getting DHCP on VLAN 101 | Verify 10G Switch relay `ip helper-address 172.16.0.85`; check `kubectl logs carbide-dhcp` |
| DPU stuck in `DpuDiscovering/Initializing` | Redfish not reachable on DPU BMC | `ncli site-explorer explore --address <DPU-BMC-IP>`; check Redfish connectivity |
| DPU stuck in `DpuDiscovering/EnableRshim` | rshim driver issue on DPU | Check BMC Redfish rshim state; may need manual `copy-bfb-to-dpu-rshim` |
| BFB install fails / stuck in `WaitForInstallComplete` | BFB task timeout or corrupt image | Try `ncli site-explorer copy-bfb-to-dpu-rshim --pre-copy-powercycle` |
| DPU in `DPUInit/DpfStates/WaitingForReady` for > 30 min | DPF operator issue | `kubectl get dpunodes -n dpf-system`; check DPF operator logs |
| Host never boots after DPU ready | DPU local DHCP server not up | Verify DPU agent is running; check `ncli dpu status` |
| DPU state shows `Failed` | State machine error | `ncli machine list` for error detail; `kubectl logs carbide-api` for context |
| `site-explorer get-report` shows Redfish error | Bad BMC credentials | Re-register with correct credentials via `ncli em replace-all` |
| BF2 detected but BFB fails | BF2 needs longer timeout | CLI auto-detects BF2 and uses extended timeout; if still failing, check rshim |
| `INVALID FW PACKAGE` on Redfish SimpleUpdate | DOCA BFB version incompatible with BMC firmware generation | [§ INVALID FW PACKAGE — BFB/BMC version mismatch](#invalid-fw-package--bfbmmc-version-mismatch) |
| `TransferFailed` / `Unknown Host` on Redfish SimpleUpdate | BMC cannot resolve `carbide-pxe.forge` — `unbound` not deployed or `carbide-dhcp` advertising the wrong nameserver VIP | [§ TransferFailed — BMC cannot download BFB](#transferfailed--bmc-cannot-download-bfb) |
| `ncli machine show` → `missing field 'state'` | `controller_state` JSON uses wrong serde tag (`"type"` instead of `"state"`) | [§ DB surgery serde tag rules](#db-surgery--correct-controller_state-json-format) |
| DPU stuck in `DPUINITIALIZING/INIT` forever | `last_discovery_time` older than `controller_state_version` — discovery check never passes | [§ DPU stuck in Init](#dpu-stuck-in-dpuinitializinginit) |
| DPU in `WaitingForNetworkConfig` — `forge-dpu-agent` never calls back | DPU booted wrong eMMC slot (old OS), cloud-init from 2025, `oob_net0` down | [§ WaitingForNetworkConfig — agent not calling back](#waitingfornetworkconfig--forge-dpu-agent-not-calling-back) |
| NICo skips `InstallingBFB` and goes straight to `WaitingForNetworkConfig` | DB reset set `last_discovery_time = NOW()` while in `Init` — state machine advanced past BFB install | [§ NICo skips BFB install](#nico-skips-bfb-install-after-db-reset) |
| `devspace deploy` fails — `no field 'machine_id' on type MachineMetrics` | Branch has stale `handler.rs` — fields moved into `.health` sub-struct, `machine_id` renamed to `object_id` | [§ carbide-api build fails — MachineMetrics](#carbide-api-build-fails--machinemetrics-field-not-found) |
| `ncli em show` → `Interface IP: Undiscovered`, `site-explorer` shows `ConnectionRefused` on the DPU BMC IP, BMC alive in-band but `lan print` shows `0.0.0.0` | DPU BMC lost its DHCP lease / bad LAN config / wedged after a failed `InstallDPUOS` | [§ DPU BMC Undiscovered — in-band reset & rediscovery](#dpu-bmc-undiscovered--in-band-reset--rediscovery) |
| DHCP reaches carbide-dhcp (`DHCPDISCOVER … NVIDIA/BF/BMC`) but allocation fails: `unable to create machine interface in fast path … after 128 retries`, `num_free_ips: 0` even on a near-empty pool | Address-less `machine_interfaces` rows squat the low FQDNs (`fqdn_must_be_unique`), jamming the per-segment IP allocator | [§ DHCP discovery jammed — fast-path FQDN squat](#dhcp-discovery-jammed--fast-path-fqdn-squat) |
| BFB `SimpleUpdate` succeeds (Task `Completed`, `PercentComplete: 100`) but DPU loops `DPUINITIALIZING/INIT` and reboots every ~45 min; `grep scout /var/log/cloud-init*.log` on the DPU is empty | `forge.bfb` is the **vanilla** NVIDIA bundle (or `preingestion.bfb`), which has **no forge-scout / cloud-init injection** → discovery never reports | [§ Vanilla vs forge BFB — Init loop, no scout](#vanilla-vs-forge-bfb--init-loop-no-scout) |
| Retry DB edit ran but **no carbide-api logs / no SimpleUpdate**; `ncli machine show` state unchanged | `jsonb_set` on `…,substate` was a **no-op** (no `substate` key while in `init`, `create_missing=false`) and/or `controller_state_version` went **backwards** (lower `V<n>` = treated as stale) | [§ Retrying BFB from `init`](#retrying-bfb-from-init--jsonb_set-no-op--version-must-increment) |
| `forge-scout.log`: `Error attempting to discover_machine … "Hardware info error: DPU Info is missing."` | scout cannot read the DPU VPD (factory MAC) — `flint -d /dev/mst/mt*_pciconf0 q full` returned nothing → `dpu_info: None`, rejected server-side | [§ Scout discovery — DPU Info is missing](#scout-discovery--dpu-info-is-missing) |
| On the DPU: `flint`/`mlxfwmanager` → `Cannot open Device … FwInit has failed!` / `Failed to open device`, `Base MAC: N/A` | NIC firmware command interface is **wedged** after a BFB flash that was never activated by a cold power-cycle; an Arm `reboot` does not reset the ASIC | [§ flint FwInit has failed — wedged NIC firmware](#flint-fwinit-has-failed--wedged-nic-firmware-cold-power-cycle-required) |

---

## Extended Troubleshooting — BFB Install Issues

The sections below are ordered to follow the **provisioning lifecycle**, so you
can read top-to-bottom or jump to the phase you're stuck in:

| Phase | Symptom | Section |
|-------|---------|---------|
| **1. Discovery / DHCP** | BMC not discovered, no lease | [DPU BMC Undiscovered](#dpu-bmc-undiscovered--in-band-reset--rediscovery), [DHCP FQDN squat](#dhcp-discovery-jammed--fast-path-fqdn-squat) |
| **2. BFB download** | `TransferFailed` / `INVALID FW PACKAGE` | [TransferFailed](#transferfailed--bmc-cannot-download-bfb), [INVALID FW PACKAGE](#invalid-fw-package--bfbmmc-version-mismatch) |
| **3. BFB image content** | Installs but never runs scout | [Vanilla vs forge BFB](#vanilla-vs-forge-bfb--init-loop-no-scout) |
| **4. Post-install / `Init`** | Loops in `Init`, reboots | [`Init` after BFB-complete is expected](#init-after-bfb-complete-is-expected), [DPU stuck in Init](#dpu-stuck-in-dpuinitializinginit), [NICo skips BFB](#nico-skips-bfb-install-after-db-reset) |
| **5. Scout / firmware probe** | `DPU Info is missing`, `FwInit has failed` | [Scout DPU Info missing](#scout-discovery--dpu-info-is-missing), [flint FwInit / wedged FW](#flint-fwinit-has-failed--wedged-nic-firmware-cold-power-cycle-required) |
| **6. Agent callback** | `WaitingForNetworkConfig` | [agent not calling back](#waitingfornetworkconfig--forge-dpu-agent-not-calling-back) |
| **DB / recovery tooling** | manual state edits, BMC resets | [DB surgery](#db-surgery--correct-controller_state-json-format), [Retrying from `init`](#retrying-bfb-from-init--jsonb_set-no-op--version-must-increment), [BMC reset vs power cycle](#bmc-cold-reset-vs-power-cycle--when-to-use-which) |
| **Production hardening** | firmware versions, external DNS | [Production hardening](#production-hardening) |
| **Build / deploy** | `cargo`/`devspace` errors | [BFB build pitfalls](#bfb-build-pitfalls-errors-during-cargo-make-build-boot-artifacts-bfb), [MachineMetrics](#carbide-api-build-fails--machinemetrics-field-not-found) |

### INVALID FW PACKAGE — BFB/BMC version mismatch

**Symptom:**

```
DPUINITIALIZING/INSTALLDPUOS { SUBSTATE: INSTALLATIONERROR {
  MSG: "BFB INSTALL TASK 0 ON SOME(172.16.x.x:443) FAILED: ...
       THE RESOURCE PROPERTY 'FIRMWARE UPDATE SERVICE' HAS DETECTED
       ERRORS OF TYPE 'INVALID FW PACKAGE'.." } }
```

The Redfish task shows:
```json
"Message": "The resource property 'Firmware Update Service' has detected errors of type 'Invalid FW Package'."
```

**Root cause:** The `forge.bfb` was built from a base DOCA BFB that is incompatible with
the DPU's BMC firmware generation. The BMC validates the BFB version before
accepting it. A DOCA 3.2.x BFB is rejected by a BF-25.x BMC; a DOCA 2.9.x BFB
is rejected by a BF-32.x BMC.

Check the DPU's BMC firmware version:
```bash
curl -sk -u root:'nutanix/4u' \
  https://<DPU_BMC_IP>/redfish/v1/Managers/Bluefield_BMC/ \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('BMC FW:', d.get('FirmwareVersion'))"
```

**Firmware → DOCA version compatibility table:**

| BMC FirmwareVersion | Compatible DOCA | `DOCA_VERSION` | `BFB_BUILD` | `BFB_RELEASE` | `DOCA_HBN_TAG` |
|---|---|---|---|---|---|
| `BF-25.x` (e.g. BF-25.10-15) | DOCA 2.9.2 | `"2.9.2"` | `"31"` | `"25.02"` | `"2.4.2-doca2.9.2-32"` |
| `BF-24.x` | DOCA 2.8.0 | `"2.8.0"` | `"11"` | `"24.04"` | `"2.3.0-doca2.8.0"` |
| `BF-32.x` | DOCA 3.2.2 | `"3.2.2"` | `"125"` | `"26.02"` | `"3.2.2-doca3.2.2"` |

**Fix:**

1. Update `pxe/Makefile.toml` with the correct version variables (see `DEPLOYMENT.md §11g`)
2. Rebuild `forge.bfb`: `cargo make build-boot-artifacts-bfb`
3. Copy new artifacts into `carbide-pxe` pod: see `DEPLOYMENT.md §11e`
4. Do a **BMC cold reset** to clear stale UpdateService state:
   ```bash
   ipmitool -I lanplus -H <DPU_BMC_IP> -U root -P 'nutanix/4u' mc reset cold
   sleep 120
   ```
5. Reset DB state to retry `InstallingBFB` (see `DEPLOYMENT.md §11f`)

> **Important:** `InstallationError` is a **terminal state** in the NICo state
> machine — the DPU will not retry automatically. Always reset the DB after a
> failed install attempt.

#### BFB build pitfalls (errors during `cargo make build-boot-artifacts-bfb`)

When rebuilding for a different DOCA version, you may hit these errors in sequence:

**Pitfall 1 — Wrong HBN image tag:**
```
Error response from daemon: failed to resolve reference
  "nvcr.io/nvidia/doca/doca_hbn:2.4.2-doca2.9.2": not found
```
The template `${DOCA_HBN_VERSION}-doca${DOCA_VERSION}` is wrong for DOCA 2.9.x.
NGC uses a build-suffix tag (e.g. `2.4.2-doca2.9.2-32`). Fix: set `DOCA_HBN_TAG`
explicitly in `pxe/Makefile.toml` and use it in `DOCA_HBN_URL`. Do not rely
on the template for DOCA 2.x versions.

**Pitfall 2 — SHA256 checksum fails:**
```
sha256sum: 'standard input': no properly formatted checksum lines found
Error while executing command, exit code: 1
```
The NGC API for DOCA 2.9.x returns `null` for `sha256_base64`. The
`download-hbn-installer-to-bfb` task must skip the checksum step when the
API returns null. Check `pxe/Makefile.toml` for conditional SHA256 logic.

**Pitfall 3 — `mv` path mismatch after download:**
```
mv: cannot stat 'temp/configs/2.9.2/': No such file or directory
```
`mv-hbn-configs-to-bfb` and `mv-hbn-scripts-to-bfb` tasks used `${DOCA_VERSION}`
as the directory key, but NGC stores files under `${DOCA_HBN_VERSION}`. Fix:
change both `mv` source paths to use `${DOCA_HBN_VERSION}` (e.g. `temp/configs/2.4.2/`).

**Pitfall 4 — `strings` output shows old version in new BFB:**
```
strings pxe/static/blobs/internal/aarch64/forge.bfb | grep bf-bundle
# shows bf-bundle-3.2.0-113_25.10...
```
This is a **false alarm** — the strings are GitHub URL comments embedded in the
Mellanox `bfb-build` shell scripts and do not reflect the actual base BFB version.
Confirm the real base BFB using:
```bash
find /tmp/bfb-dump/ -name "bf-bundle-*.bfb" | xargs ls -lh
# Should show: bf-bundle-2.9.2-31_25.02_ubuntu-22.04_prod.bfb
```

---

### Why a dedicated `unbound` instead of reusing `carbide-dns`?

A common question when wiring up DNS on the OOB network: *we already have
`carbide-dns` listening on 172.16.0.87, why can't the BMC just use that for
`carbide-pxe.forge`?*

Short answer: **they solve different problems and are intentionally separate
services.** The OOB network needs a resolver that hosts the static `.forge`
zone — that's what `unbound` is for. `carbide-dns` is a different service
serving a completely different concern (tenant/VPC dynamic records).

#### What each service is

| Service | Implementation | Purpose | Records it owns |
|---|---|---|---|
| `carbide-dns` | Custom Rust DNS server (`crates/dns/`) backed by the NICo gRPC API + Postgres | Resolve **tenant/VPC** in-band DNS records that are created dynamically by NICo when instances/networks are provisioned (e.g. `<vm-name>.<vpc>.<tenant>.local`) | Per-VPC zones written through the NICo API; nothing static |
| `unbound` | Stock recursive resolver (NLnetLabs unbound) with a static `local-data` config | Resolve the well-known `.forge` zone (`carbide-pxe.forge`, `carbide-api.forge`, etc.) AND recursively resolve public names for clients on the OOB network | The static `.forge` zone seeded from `localConfig.local_data.conf`; forwards everything else to upstream resolvers (8.8.8.8, 1.1.1.1) |

#### Why not just teach `carbide-dns` about `.forge`?

You could, but it would be wrong:

1. **`carbide-dns` is API-driven, not file-driven.** Every record it serves
   has to be created through a gRPC call into `carbide-api`. The `.forge`
   names map to **MetalLB VIPs** — they have nothing to do with NICo's
   tenant model and no `carbide-api` call should ever create or delete them.
   Forcing a static infra zone into an API-driven service blurs a clean
   separation and creates a chicken-and-egg problem at bootstrap (you can't
   call `carbide-api` to register `carbide-api.forge` until `carbide-api`
   itself is reachable — which requires resolving `carbide-api.forge`).

2. **`carbide-dns` is not a recursive resolver.** It can only answer for
   zones it knows about. BMCs and DPU agents also need to resolve external
   names (NTP, container registries, telemetry endpoints) on the OOB
   network. A separate recursive resolver is needed regardless of whether
   we put `.forge` in `carbide-dns` or unbound.

3. **`carbide-dns` is replicated and authoritative-only by design.** It's
   two pods (`172.16.0.87` and `172.16.0.88` in this lab) on separate
   instances for HA of tenant records. Mixing infrastructure records into
   the same DB would couple infra availability to NICo's tenant-record
   serving path.

4. **Image size and supply chain.** unbound is one battle-tested 5 MB
   binary you can rebuild from upstream tarballs and own the CVE response
   for (`dev/docker/unbound/Dockerfile`). `carbide-dns` is part of the NICo
   codebase and rebuilds whenever NICo does. Keeping the `.forge` resolver
   independent of NICo's build cadence means an OOB-network DNS outage
   doesn't require a NICo upgrade to fix.

#### Why the `unbound_exporter` sidecar?

unbound exposes operational state (cache hit rate, NXDOMAIN counters,
query latency histograms, per-zone response counts) over a TLS-protected
control channel. `unbound_exporter` is a small Go process that connects to
that channel and translates the stats into Prometheus metrics. The chart
runs it as a sidecar on the same Pod because:

- It needs `unbound_control.key` + `unbound_control.pem` (auto-generated
  on first boot by `unbound-control-setup`) — the easiest way to share
  those is an emptyDir volume mounted into both containers.
- One scrape target per Pod, no cross-Pod TLS PKI plumbing.
- Lifecycle is one-to-one: if unbound is unhealthy, the exporter should
  also surface its stats as stale; co-locating makes that automatic.

If you don't care about DNS metrics in your monitoring stack you can
disable the sidecar by removing the second container from the chart's
Deployment, but the chart ships it by default because the rest of NICo's
observability story (Prometheus + Grafana dashboards) already expects
these metrics to be available.

#### Quick summary

```
                    .forge name?
                    /        \
                  Yes        No
                  /           \
            unbound       carbide-dns (tenant/VPC zones)
                |
       MetalLB VIP 172.16.0.91
                |
        carbide-dhcp advertises this VIP as DNS server
                |
        BMCs / DPU agents on OOB network query 172.16.0.91
```

---

### TransferFailed — BMC cannot download BFB

**Symptom:** Redfish task shows:

```json
"Message": "Transfer of image '/public/blobs/internal/aarch64/forge.bfb' to '/dev/rshim0/boot' failed.",
"Resolution": "Unknown Host: ... Check and restart server's web service (for HTTP/HTTPS download)"
```

Followed by `Invalid FW Package` — the secondary error always appears when transfer fails.

There are **two distinct root causes** for this error — check both:

#### Root cause — `.forge` zone has no resolver on the OOB network

NICo hardcodes `carbide-pxe.forge//path` in the Redfish `ImageURI`
(`crates/api/src/state_controller/machine/handler.rs`, search for
`forge.bfb`). The DPU BMC must therefore resolve `carbide-pxe.forge` to the
carbide-pxe LoadBalancer VIP. The `.forge` zone is hosted by **unbound**, a
recursive DNS resolver that lives at `helm/charts/unbound/`.

> **Why this fails so often in dev:** the umbrella chart ships with
> `unbound.enabled: false` and `carbide-dhcp` historically advertised
> `127.0.0.1` (or the carbide-dns VIP at `172.16.0.87`) as the nameserver.
> `carbide-dns` is **not** the `.forge` zone — it serves tenant/VPC records
> through the NICo API. Pointing the BMC at `172.16.0.87` will return
> NXDOMAIN for `carbide-pxe.forge`.

**Diagnose:**
```bash
# 1. Does anything in the cluster resolve carbide-pxe.forge?
kubectl get pods -n forge-system | grep -E "forge-unbound|unbound"

# 2. From a host on the OOB network (e.g. nico-cp-1):
dig carbide-pxe.forge @<DNS_VIP> +short
# Expected: 172.16.0.86 (the carbide-pxe VIP)

# 3. Confirm carbide-pxe is reachable on port 80 via its VIP:
curl -s -o /dev/null -w "%{http_code}\n" \
  http://172.16.0.86/public/blobs/internal/aarch64/forge.bfb
# Must return 200

# 4. Confirm BMC DNS is set:
curl -sk -u root:'nutanix/4u' \
  https://<DPU_BMC_IP>/redfish/v1/Managers/Bluefield_BMC/EthernetInterfaces/eth0 \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('NameServers:', d.get('NameServers'), 'Static:', d.get('StaticNameServers'))"
```

**Fix — deploy `unbound` with the `.forge` zone exposed on a LoadBalancer VIP:**

The dev `values.base.yaml` enables an `unbound` deployment that:
- Pins itself to MetalLB VIP `172.16.0.91` (`externalService.enabled: true`)
- Seeds the `.forge` zone via `localConfig.local_data.conf` with A records
  for `carbide-api.forge`, `carbide-pxe.forge`, `carbide-static-pxe.forge`,
  `carbide-ntp.forge`, and `unbound.forge`
- Is advertised by `carbide-dhcp` (`carbide-nameservers: 172.16.0.91`) so
  new DHCP clients pick it up automatically — no per-BMC patching needed

> **VIP allocation note:** `172.16.0.90` is reserved for `carbide-ssh-console`
> in the IP plan (see [DEPLOYMENT.md § IP plan](DEPLOYMENT.md#ip-plan)). The
> `.forge` resolver uses **`172.16.0.91`** — make sure these are not confused.

To deploy:
```bash
cd <repo>
export SQUID_PROXY=http://172.16.0.50:3128
devspace deploy -n forge-system --force-deploy

# Verify pod and VIP
kubectl get pods,svc -n forge-system | grep unbound
# Expected:
#   pod/forge-unbound-...                Running
#   service/forge-unbound                ClusterIP    53/UDP,53/TCP
#   service/forge-unbound-external       LoadBalancer 172.16.0.91  53/UDP,53/TCP

# Verify the .forge zone is loaded
kubectl exec -n forge-system deployment/forge-unbound -- \
  cat /etc/unbound/local.conf.d/local_data.conf

# Verify resolution from nico-cp-1
dig carbide-pxe.forge @172.16.0.91 +short
# Expected: 172.16.0.86
```

**For DPU BMCs already DHCP'd with the old (broken) nameserver, re-patch
their static DNS once — they'll pick up the new value on next DHCP renewal:**
```bash
curl -sk -u root:'nutanix/4u' \
  -H 'Content-Type: application/json' \
  -X PATCH \
  -d '{"StaticNameServers": ["172.16.0.91"]}' \
  https://<DPU_BMC_IP>/redfish/v1/Managers/Bluefield_BMC/EthernetInterfaces/eth0
```

> **Note:** A `mc reset cold` wipes `StaticNameServers` back to `[]`. After
> any cold reset, either re-patch DNS manually or wait for DHCP renewal
> (since `carbide-dhcp` now advertises `172.16.0.91`). The latter is the
> correct path — manual patching should not be needed once unbound is
> deployed and DHCP is configured.

> **Pitfall — stale active `NameServers`:** even after setting
> `StaticNameServers: ["172.16.0.91"]`, the BMC may still show the **old**
> DHCP-learned resolver merged in `NameServers (active)`:
> ```text
> NameServers (active): ['172.16.0.91', '172.16.0.87']
> StaticNameServers:    ['172.16.0.91']
> DHCPv4.UseDNSServers: True
> ```
> The BMC queries in list order, so a query for `carbide-pxe.forge` may go
> to `172.16.0.87` (carbide-dns, NXDOMAIN for `.forge`) and never reach
> `172.16.0.91`. Two ways to fix:
>
> 1. **Disable DHCP-supplied DNS on the BMC** so only `StaticNameServers`
>    is used:
>    ```bash
>    curl -sk -u root:'nutanix/4u' -H 'Content-Type: application/json' \
>      -X PATCH \
>      -d '{"DHCPv4":{"UseDNSServers": false}}' \
>      https://<DPU_BMC_IP>/redfish/v1/Managers/Bluefield_BMC/EthernetInterfaces/eth0
>    ```
> 2. **Force a DHCP renewal** so the BMC picks up the new
>    `carbide-nameservers: 172.16.0.91` value (BMC cold reset, or bounce
>    `eth0`). After the renewal, `NameServers (active)` should contain
>    only `172.16.0.91`.

---

#### Reference — why the `host//path` `ImageURI` format is correct

Despite the error message saying `Unknown Host`, the `ImageURI` format itself
is **not** the issue. NVIDIA's BlueField BMC uses a non-standard URI format
for `ImageURI` when `TransferProtocol` is set separately in the request body:

```
<server>//path/to/file.bfb      ← correct per NVIDIA docs (DO NOT add http://)
```

Per [NVIDIA BlueField BMC docs](https://docs.nvidia.com/networking/display/bluefieldbmcv2504/Deploying+BlueField+Software+Using+BFB+from+BMC):
> `image_uri` — contains both the HTTP server address and the exported path
> to the `.bfb` file on the server, **with one slash between the two fields**
> (i.e., `/`).

Example from docs: `"ImageURI":"10.10.10.10//tmp/file.bfb"` — `server//path`.

So `carbide-pxe.forge//public/blobs/internal/aarch64/forge.bfb` is the
**correct** format. Adding `http://` prefix breaks it: the BMC strips the
scheme and treats `//carbide-pxe.forge/...` as an absolute path, giving the
same `Unknown Host` error.

> **Diagnostic:** Look at `Payload.JsonBody` in the failed Redfish task:
> ```bash
> curl -sk -u root:'nutanix/4u' https://<DPU_BMC_IP>/redfish/v1/TaskService/Tasks/<N> \
>   | python3 -c "import sys,json; d=json.load(sys.stdin); import json as j; print(j.loads(d['Payload']['JsonBody'])['ImageURI'])"
> ```
> - `carbide-pxe.forge//public/...`  → URI is correct; the problem is DNS
>   resolution (NXDOMAIN or empty `NameServers` on the BMC)
> - `/carbide-pxe.forge/public/...`  → someone added `http://` prefix; revert
>   `crates/api/src/state_controller/machine/handler.rs` to the bare
>   `carbide-pxe.forge//path` form
> - `/public/...` (no host at all) → BMC parser dropped the host; same
>   `http://`-prefix root cause as above

---

### DB surgery — correct `controller_state` JSON format

**Symptom:** `ncli machine show` returns:
```
Database Error: error occurred while decoding column "host_snapshot":
missing field `state` at line 1 column 264
```

**Root cause:** `ManagedHostState` uses `#[serde(tag = "state", rename_all = "lowercase")]`.
The JSON discriminant key **must be `"state"`**, not `"type"` or any other key.
`DpuInitState` uses `#[serde(tag = "dpustate", rename_all = "lowercase")]`.

**Correct JSON formats for common reset operations:**

```sql
-- Host row: reset to Created (restarts DPU provisioning lifecycle)
UPDATE machines SET controller_state = '{"state":"created"}' WHERE id = '<HOST_ID>';

-- Host row: DPUInit with DPU in Init substate
UPDATE machines SET controller_state =
  '{"state":"dpuinit","dpu_states":{"states":{"<DPU_ID>":{"dpustate":"init"}}}}'
WHERE id = '<HOST_ID>';

-- Host row: force retry of BFB install (skips Init/discovery wait)
UPDATE machines SET controller_state =
  '{"state":"dpuinit","dpu_states":{"states":{"<DPU_ID>":{"dpustate":"installdpuos","substate":{"installdpuosstate":"installingbfb"}}}}}'
WHERE id = '<HOST_ID>';
```

> **Critical:** Always update the **host machine row** (`fm100ps...`), not the
> DPU row. The state machine runs on the host row's `controller_state.dpu_states`
> map. The DPU row's `controller_state` is a mirror updated by NICo.

Always pair state changes with a version bump and cleared reboot fields:
```sql
UPDATE machines
SET controller_state         = '<json>',
    controller_state_version = 'V1-T' || floor(EXTRACT(EPOCH FROM NOW()) * 1000000)::bigint,
    last_reboot_requested    = NULL,
    last_reboot_time         = NULL,
    last_discovery_time      = NULL
WHERE id = '<HOST_ID>';
```

> **Version must move *forward*.** `V1-T…` is only safe when you are certain the
> live `version_nr` is lower. If the row is already at, say, `V3`, writing `V1`
> makes the processor treat the change as **stale** and silently skip it (no
> logs, no action), and can collide with existing `machine_state_history` rows.
> When in doubt, **increment** from the current value instead — see
> [§ Retrying BFB from `init`](#retrying-bfb-from-init--jsonb_set-no-op--version-must-increment)
> for the `V<current+1>` expression. Also note `jsonb_set(…, false)` is a no-op
> if the target path doesn't exist (e.g. patching `…,substate` while in `init`).

---

### DPU stuck in `DPUINITIALIZING/INIT`

**Symptom:** DPU stays in `DPUINITIALIZING/INIT` indefinitely. Logs show:
```
"Waiting for DPU <ID> discovery and reboot"
```

**Root cause:** The `Init` handler checks `last_discovery_time > controller_state_version.timestamp()`.
If `last_discovery_time` is NULL, older than the version timestamp, or set at
the exact same second as the version, the check fails and NICo loops issuing
Redfish reboots without advancing.

**Diagnose:**
```sql
SELECT id,
       controller_state_version,
       last_discovery_time,
       controller_state_outcome
FROM machines
WHERE id IN ('<HOST_ID>', '<DPU_ID>');
```

Convert version timestamp: `python3 -c "import datetime; print(datetime.datetime.utcfromtimestamp(<EPOCH_MICROS>/1000000))"`

**Fix:** Set `last_discovery_time` to strictly after `controller_state_version` timestamp.
**Do NOT also bump `controller_state_version`** — that would reset the baseline
and make the new `last_discovery_time` old again:
```sql
UPDATE machines
SET last_discovery_time   = NOW(),
    last_reboot_requested = NULL,
    last_reboot_time      = NULL
WHERE id IN ('<HOST_ID>', '<DPU_ID>');
```

After this NICo will call `handler_restart_dpu` (Redfish DPU reboot) and
transition to `WaitingForPlatformPowercycle`.

---

### NICo skips BFB install after DB reset

**Symptom:** After resetting DB state to `{"dpustate":"init"}` and then setting
`last_discovery_time = NOW()`, NICo advances through `Init` →
`WaitingForPlatformPowercycle` → `WaitingForPlatformConfiguration` →
`WaitingForNetworkConfig` — **without ever submitting a Redfish SimpleUpdate**.
No new Redfish tasks appear. DPU is still running the old OS.

**Root cause:** The `Init` substate is a *discovery wait + reboot trigger*, not
a BFB install trigger. Once `last_discovery_time > version`, `Init` calls
`handler_restart_dpu` and moves to `WaitingForPlatformPowercycle`. The
`InstallDpuOs/InstallingBFB` substate must be set **explicitly** to make NICo
call `SimpleUpdate`.

**Fix:** Set the **host row** directly to `installingbfb`:
```sql
-- Enter psql (no shell quoting issues):
-- kubectl exec -n forge-system -it deployment/carbide-api -- psql "${DATABASE_URL}"

UPDATE machines
SET controller_state =
  '{"state":"dpuinit","dpu_states":{"states":{"<DPU_ID>":{"dpustate":"installdpuos","substate":{"installdpuosstate":"installingbfb"}}}}}',
    controller_state_version = 'V1-T' || floor(EXTRACT(EPOCH FROM NOW()) * 1000000)::bigint,
    last_reboot_requested    = NULL,
    last_reboot_time         = NULL,
    last_discovery_time      = NULL
WHERE id = '<HOST_ID>';
```

NICo will call `SimpleUpdate` within one poll cycle (~30s). Confirm with:
```bash
kubectl logs -n forge-system deployment/carbide-api -f \
  | grep -E "install task|SimpleUpdate|InstallingBFB|forge\.bfb"
# Look for: "DPU <ID> OS install task <N> submitted."
```

Then monitor the Redfish task:
```bash
curl -sk -u root:'nutanix/4u' \
  https://<DPU_BMC_IP>/redfish/v1/TaskService/Tasks/<N> | python3 -m json.tool
```

---

### `Init` after BFB-complete is expected

**Not a bug.** After a successful BFB install the DPU substate transitions back
to `init` — this is the *landing* state, not a failure:

```
InstallDpuOs/InstallingBFB → WaitForInstallComplete → Completed → DpuInit/Init
```

The code path is explicit (`crates/api/src/state_controller/machine/handler/helpers.rs`):
`InstallDpuOsState::Completed => DpuInitState::Init.next_state(...)`, mirrored by
the canonical history fixture in `crates/api/src/tests/machine_history.rs`
(`installingbfb` → `waitforinstallcomplete` → `init`).

In `Init` the DPU reboots into the freshly-flashed DOCA OS, cloud-init runs
**forge-scout**, and scout's `DiscoveryCompleted` RPC sets `last_discovery_time`.
Only then does it advance out of `Init`. If discovery doesn't arrive within the
wait window, the watchdog reboots the DPU (up to 15 cycles, then
`ManualInterventionRequired`). So "back to init after a 100% install" is success
— the work now shifts to **getting scout to report** (the next sections).

> The `InsertMachineHealthReport` calls you see from a `10.244.x` (pod) address
> are `carbide-hardware-health` polling the DPU **BMC over Redfish** — they do
> **not** prove the DPU OS booted. Proof of a booted OS is scout traffic from
> the DPU's own `172.16.0.x` address.

---

### Vanilla vs forge BFB — Init loop, no scout

**Symptom:** BFB `SimpleUpdate` completes cleanly (`TaskState: Completed`,
`PercentComplete: 100`, `Device 'DPU' successfully updated`), the DPU boots a
DOCA OS (`uname -r` → `*-bluefield`), but it **loops in `DPUINITIALIZING/INIT`**
and the watchdog reboots it every ~45 min. On the DPU:

```bash
grep -ri scout /var/log/cloud-init*.log     # EMPTY → scout was never installed
ls /opt/forge/forge-scout                    # missing
ls /var/lib/cloud/seed/nocloud-net/user-data # missing
```

**Root cause:** the `forge.bfb` being served is a **vanilla NVIDIA `bf-bundle`**
(or the `preingestion.bfb` copy), which contains **none** of the forge
customization. NICo's scout/agent are injected only by the forge BFB build.
There are two distinct BFBs:

| File (in `pxe/static/blobs/internal/aarch64/`) | Built by | Contains scout / cloud-init? | Use |
|---|---|---|---|
| `preingestion.bfb` | `save-bfb-for-preingestion` (copies the **vanilla** download) | **No** | pre-ingestion only |
| `forge.bfb` | `build-boot-artifacts-bfb` (`bfb-add-scout-to-bfb`, `cp-forge-dpu-package-to-bfb`, `bfb-rebuild-bfb`) | **Yes** | the one NICo flashes |

The forge build embeds the `pxe/templates/user-data` install hook
(`carbide_modify_os`), which writes `/var/lib/cloud/seed/nocloud-net/user-data`
with `run-scout.sh`, the `forge-dpu.deb`, HBN config, and the forge root CA. A
vanilla bundle has none of this, so the DPU boots plain Ubuntu, never runs
scout, never reports discovery → infinite `Init` loop.

**Confirm which BFB is served** (it must differ from the vanilla `preingestion.bfb`):
```bash
POD=$(kubectl get pod -n forge-system -l app.kubernetes.io/name=carbide-pxe -o jsonpath='{.items[0].metadata.name}')
kubectl exec -n forge-system "$POD" -- ls -lh /boot-artifacts/blobs/internal/aarch64/
# forge.bfb should be hundreds of MB LARGER than preingestion.bfb (scout/debs/HBN)
```

**Fix:** build a real forge BFB (DOCA version matching the BMC generation — see
[INVALID FW PACKAGE table](#invalid-fw-package--bfbmmc-version-mismatch)),
serve it, then retry the install:
```bash
cargo make build-boot-artifacts-bfb      # produces pxe/static/blobs/internal/aarch64/forge.bfb
kubectl cp pxe/static/blobs/internal/aarch64/forge.bfb \
  forge-system/"$POD":/boot-artifacts/blobs/internal/aarch64/forge.bfb
# then re-arm InstallingBFB per the next section, mc reset cold the DPU BMC, and let it reflash
```

> **Survives redeploys?** No — the artifact lives in an `emptyDir`, wiped on pod
> restart. Wire it up via `bootArtifactContainers` so it's repopulated
> automatically; otherwise every redeploy needs the `kubectl cp` again, and a
> missing file gives a `404`/`TransferFailed` on the next install.

---

### Retrying BFB from `init` — `jsonb_set` no-op + version must increment

**Symptom:** you ran a `jsonb_set` retry to push the DPU back to `installingbfb`,
but **nothing happened** — no `SimpleUpdate`, no carbide-api logs, `ncli machine
show` state unchanged.

**Two traps, both must be avoided:**

1. **`jsonb_set` is a no-op when the path doesn't exist.** While the DPU is in
   `Init`, its state node is just `{"dpustate":"init"}` — there is **no
   `substate` key**. A `jsonb_set(…, '{…,substate}', …, false)` (create-missing
   = `false`) therefore changes nothing, and `dpustate` stays `init`. You must
   replace the **whole DPU node**, not just `substate`:

   ```sql
   UPDATE machines
   SET controller_state = jsonb_set(
         controller_state,
         '{dpu_states,states,<DPU_ID>}',
         '{"dpustate":"installdpuos","substate":{"installdpuosstate":"installingbfb"}}'::jsonb,
         true                                   -- create-missing = true
       ),
       controller_state_version = 'V' || (
         (split_part(split_part(controller_state_version,'-',1),'V',2))::bigint + 1
       ) || '-T' || floor(extract(epoch from now())*1000000)::bigint,
       last_reboot_requested = NULL,
       last_reboot_time      = NULL,
       last_discovery_time   = NULL
   WHERE id = '<HOST_ID>';
   ```

2. **`controller_state_version` must *increment*, never go backwards.** The
   format is `V<version_nr>-T<micros>` (`crates/config-version/src/lib.rs`).
   Writing a **lower** `V<n>` than the live value (e.g. `V1` over a live `V3`)
   makes the processor treat the row as **stale** and skip it — hence "no logs
   at all". Reusing a low number can also collide with existing
   `machine_state_history` rows. The expression above derives `V<current+1>`
   from the existing version so it always moves forward.

**Verify before waiting on logs:**
```sql
SELECT controller_state_version, jsonb_pretty(controller_state)
FROM machines WHERE id = '<HOST_ID>';
-- version_nr bumped, and the DPU node now shows dpustate=installdpuos / installingbfb
```

> The earlier [§ NICo skips BFB install](#nico-skips-bfb-install-after-db-reset)
> snippet works only because it sets the **whole** `controller_state` (so
> `dpustate` becomes `installdpuos`). When *patching* an existing row in `init`,
> use the whole-node `jsonb_set` above with an incrementing version.

---

### Scout discovery — DPU Info is missing

**Symptom:** scout is running (so the forge BFB is correct), but
`/var/log/forge/forge-scout.log` shows repeated:

```
level=ERROR msg="Error attempting to discover_machine (attempt: N):
  code: 'Internal error', message: \"Hardware info error: DPU Info is missing.\""
```

**Root cause:** carbide-api rejects the discovery because the `HardwareInfo`
scout sent has `dpu_info: None`. The server needs the DPU's **factory MAC**
(`HardwareInfo::factory_mac_address()` → `HardwareInfoError::MissingDpuInfo`
in `crates/api-model/src/hardware_info.rs`). scout populates `dpu_info` by
shelling out to **`flint`** (`crates/host-support/src/hardware_enumeration/dpu.rs`,
`get_flint_query` → `flint -d /dev/mst/mt*_pciconf0 q full`). If that command
returns nothing/errors, `dpu_info` stays `None` and discovery fails.

**Diagnose on the DPU** (`ssh ubuntu@<DPU_IP>`):
```bash
ls -l /dev/mst/                                   # device nodes present?
sudo mst status -v                                # BlueField device listed?
sudo timeout 120 flint -d /dev/mst/mt*_pciconf0 q full | grep -E 'Base MAC|FW Version|Part Number'
```

If `flint` returns a real `Base MAC`, scout will succeed on its next attempt
(or run `sudo /opt/forge/run-scout.sh` once — see the contention warning below).
If `flint` errors with `FwInit has failed!`, go to the next section.

---

### flint `FwInit has failed` — wedged NIC firmware (cold power-cycle required)

**Symptom:** on the DPU, every MFT tool fails to *open* the device:
```
$ sudo flint -d /dev/mst/mt41692_pciconf0 q full
-E- Cannot open Device: /dev/mst/mt41692_pciconf0. FwInit has failed!

$ sudo mlxfwmanager --query
  ... Base MAC: N/A   FW: --   Status: Failed to open device
```
`mlxconfig` may still print the PCI-level identity (name/description come from
PCI config space), but firmware fields (`Base MAC`, `PSID`, `FW`) are empty.

**Root cause:** the NIC firmware command interface (ICMD) is **wedged**. The BFB
**flashes NIC firmware**, and a flash requires a **firmware reset / cold
power-cycle to activate**; until then the firmware sits in a pending state the
tools can't open. An Arm OS `sudo reboot` restarts **only the Arm cores** — it
does **not** reset the BlueField ASIC, so the wedge survives a reboot.

> In the normal automated flow this is handled by the
> `WaitingForPlatformPowercycle` DPU state, which issues a real host
> `ForceOff → On` (a `dpu_impacting_action` in `handler.rs`). Manually
> DB-jumping the state to `installingbfb`/`init` **bypasses** that power-cycle —
> which is how you end up wedged.

**Two contributing pitfalls:**
- **Concurrent access.** Running `flint`/`run-scout.sh` by hand *while cloud-init
  is still running scout* (`cloud-init status` = `running`) means two processes
  hit the firmware semaphore at once → hang / `FwInit`. Only ever run **one**
  flint/scout at a time. `pkill -9 flint` mid-operation can also leave the tools
  semaphore stuck (clear with `flint -d <dev> --clear_semaphore`).
- `mst` showing `MST PCI module is not loaded` (only *pciconf* loaded) is
  **normal** on BlueField — not the cause.

**Fix — cold power-cycle the DPU to activate the flash:**
```bash
# 1) (optional) in-band firmware reset, if the device can still be opened:
sudo mlxfwreset -d /dev/mst/mt41692_pciconf0 -l 3 -y reset

# 2) the reliable fix — cold-cycle from the DPU's integrated BMC:
ipmitool -I lanplus -H <DPU_BMC_IP> -U root -P '<bmc-pass>' chassis power cycle
#    (or Redfish ComputerSystem.Reset {"ResetType":"PowerCycle"})
# 3) if still wedged, full A/C power-cycle the x86 host the DPU card sits in.

# 4) verify firmware is openable again (real Base MAC, not N/A):
ssh ubuntu@<DPU_IP> 'sudo mlxfwmanager --query 2>&1 | grep -E "Base MAC|FW|Status"'
```

After a successful cold-cycle, `flint … q` returns a real `Base MAC`, scout's
`get_dpu_info()` succeeds, `DiscoveryCompleted` fires, and the DPU leaves `Init`.
If it *still* says `Failed to open device` after a full host A/C cycle, suspect
NIC-FW corruption from the flash and re-flash NIC FW (`flint … burn`).

---

### WaitingForNetworkConfig — forge-dpu-agent not calling back

**Symptom:** DPU stuck in `WaitingForNetworkConfig`. DB shows:
- `network_status_observation` = NULL
- `dpu_agent` health = NULL

SSH to DPU ARM OS (`ubuntu@<DPU_IP>`) shows cloud-init logs from **2025** — the
DPU booted the old eMMC slot (pre-NICo OS), not the newly installed `forge.bfb`.

**Diagnose:**
```bash
# SSH to DPU ARM
ssh ubuntu@<DPU_IP>

# Check which OS is running
cat /etc/mlnx-release
# If shows bf-bundle-3.2.1 or older → wrong eMMC slot

# Check cloud-init timestamp
tail -5 /var/log/cloud-init-output.log
# If shows 2025 dates → old OS, cloud-init already ran, won't re-run

# Check oob_net0
ip link show oob_net0   # Should be UP with an IP
# If DOWN → mgmt VRF never configured → forge-scout can't reach carbide-api
```

**Fix A — wrong eMMC slot:** Switch to the alternate (newly installed) slot:
```bash
# On the DPU
sudo mlxbf-bootctl          # shows current/alternate slots
sudo mlxbf-bootctl -s 1     # switch to slot 1
sudo reboot
```

Or via Redfish from nico-cp-1:
```bash
curl -sk -u root:'nutanix/4u' \
  -H 'Content-Type: application/json' \
  -X POST \
  -d '{"ResetType":"GracefulRestart"}' \
  https://<DPU_BMC_IP>/redfish/v1/Systems/Bluefield/Actions/ComputerSystem.Reset
```

After reboot `cat /etc/mlnx-release` must show `bf-bundle-2.9.2-31...` (the
NICo-built BFB version). Cloud-init will run `runcmds.sh` for the first time,
install `forge-dpu.deb`, and run `forge-scout` to call back.

**Fix B — oob_net0 down (mgmt VRF missing):** Bring up manually to diagnose:
```bash
sudo ip link set oob_net0 up
sudo dhclient oob_net0 -v
ip vrf show    # mgmt VRF should appear after DHCP
```

**Fix C — cloud-init stale cache on correct new OS:**
```bash
sudo cloud-init clean --logs
sudo cloud-init init --local
sudo reboot
```

**Monitor after fix:**
```bash
# On DPU
sudo tail -f /var/log/cloud-init-output.log
# Look for: "dpkg: forge-dpu" and "starting forge-scout"

# On nico-cp-1 — watch DB update
kubectl exec -n forge-system -it deployment/carbide-api -- psql "${DATABASE_URL}" -c "
  SELECT id, network_status_observation->>'observed_at', health_reports->'merges'->'dpu_agent'
  FROM machines WHERE id = '<DPU_ID>';" 
# network_status_observation should populate within ~60s of forge-scout running
```

Once `network_status_observation` is populated with `network_config_version`
matching the host's `network_config.version`, NICo automatically advances to
`HostInit`.

---

### carbide-api build fails — `MachineMetrics` field not found

**Symptom:** `devspace deploy --force-deploy` fails with:

```
error[E0609]: no field `machine_id` on type `&mut MachineMetrics`
   --> crates/api/src/state_controller/machine/handler.rs:523:21
     = note: available fields are: `agent_versions`, `dpus_up`, ... and 13 others

error[E0609]: no field `health_probe_alerts` on type `&mut MachineMetrics`
   --> handler.rs:545:18
   help: one of the expressions' fields has a field of the same name
     |  .health.health_probe_alerts

error[E0609]: no field `health_alert_classifications` ...
error[E0609]: no field `alerts_suppressed` ...
error[E0609]: no field `num_merge_overrides` ...
error[E0609]: no field `replace_override_enabled` ...
```

**Root cause:** The Docker build image's version of `metrics.rs` refactored
several `MachineMetrics` fields into a nested `health` sub-struct, but
`handler.rs` on this branch was not updated to match. The local `metrics.rs`
still has the fields at the top level (so local `cargo build` may not catch it),
but the Docker build uses the newer struct layout.

The affected fields and their renamed paths:

| Old (broken) | New (correct) |
|---|---|
| `ctx.metrics.machine_id` | `ctx.metrics.health.object_id` |
| `ctx.metrics.health_probe_alerts` | `ctx.metrics.health.health_probe_alerts` |
| `ctx.metrics.health_alert_classifications` | `ctx.metrics.health.health_alert_classifications` |
| `ctx.metrics.alerts_suppressed` | `ctx.metrics.health.alerts_suppressed` |
| `ctx.metrics.num_merge_overrides` | `ctx.metrics.health.num_merge_overrides` |
| `ctx.metrics.replace_override_enabled` | `ctx.metrics.health.replace_override_enabled` |

> **Note:** `machine_id` was additionally renamed to `object_id` inside the
> `.health` sub-struct. The compiler suggests `.health.machine_id` but the
> actual field is `.health.object_id` — always confirm with the struct definition
> when the compiler hint and the available fields list disagree.

**Fix:** In `crates/api/src/state_controller/machine/handler.rs` around line 523:

```rust
// Before (broken):
ctx.metrics.machine_id = state.host_snapshot.id.to_string();
// ...
ctx.metrics.health_probe_alerts.insert(...);
ctx.metrics.health_alert_classifications.insert(c.clone());
ctx.metrics.alerts_suppressed = true;
ctx.metrics.num_merge_overrides = ...;
ctx.metrics.replace_override_enabled = ...;

// After (correct):
ctx.metrics.health.object_id = state.host_snapshot.id.to_string();
// ...
ctx.metrics.health.health_probe_alerts.insert(...);
ctx.metrics.health.health_alert_classifications.insert(c.clone());
ctx.metrics.health.alerts_suppressed = true;
ctx.metrics.health.num_merge_overrides = ...;
ctx.metrics.health.replace_override_enabled = ...;
```

These were pre-existing broken changes on the branch — triggered into visibility
when any other change to `handler.rs` caused a full recompile inside Docker.

> **Note:** During debugging of the `TransferFailed` error, `http://` was
> temporarily added to the `ImageURI` in `handler.rs`. This was **incorrect**
> and has been reverted. The BlueField BMC expects `host//path` format (no
> scheme prefix) when `TransferProtocol` is specified separately — per NVIDIA
> docs. Adding `http://` causes the BMC to log
> `/carbide-pxe.forge/public/...` (treats scheme as path), which is worse.

---

### BMC cold reset vs. power cycle — when to use which

| Operation | Command | When to use |
|---|---|---|
| **Power cycle** | `ipmitool power cycle` | Normal reboot — does NOT reset BMC UpdateService state |
| **BMC cold reset** | `ipmitool mc reset cold` | After failed Redfish `SimpleUpdate` — clears task queue and UpdateService in-memory state. BMC unreachable for ~2 min. |
| **Redfish restart** | `POST .../Systems/Bluefield/Actions/ComputerSystem.Reset {"ResetType":"GracefulRestart"}` | Reboot DPU ARM OS via Redfish — does not reset BMC |

Always use `mc reset cold` after any `INSTALLATIONERROR` before retrying the BFB install.

---

### DPU BMC Undiscovered — in-band reset & rediscovery

**Symptom:**

```text
# ncli em show
| Serial Number | BMC Mac           | Interface IP |  ...
| MT2615605K5G  | 84:EB:0C:5B:59:B1 | Undiscovered |  ... Unlinked

# ncli site-explorer get-report endpoint
| 172.16.0.23 | Unknown | | | | Initial | | {"Type":"ConnectionRefused", ... https://172.16.0.23:443/redfish/v1/ ...}
```

`Interface IP: Undiscovered` means NICo has **no `machine_interface` row** for
that BMC MAC (the `em show` table keys on the BMC MAC; see
`crates/admin-cli/src/expected_machines/show/cmd.rs`). The BMC simply isn't on
the network yet — it has no DHCP lease and Redfish refuses on its expected IP.

> **BlueField MAC gotcha:** the DPU exposes consecutive MACs — `…:b0` is the
> **ARM/UEFI OOB** interface (`oob_net0`, the one you SSH into) and `…:b1` is
> the **integrated BMC**. If you can `ssh ubuntu@<ip>` to the BMC's "expected"
> IP, you're on the ARM OS, **not** the BMC. The ARM OS does not serve Redfish,
> which is why `site-explorer` logs `ConnectionRefused` there.

#### Step 1 — Reach the BMC in-band from the DPU ARM OS

The BlueField BMC is reachable from the ARM OS over **IPMB** (not KCS), but the
device node must exist first:

```bash
sudo modprobe ipmi_msghandler
sudo modprobe ipmi_devintf          # creates /dev/ipmi0
# NOTE: do NOT modprobe ipmi_si — it probes for KCS hardware that BlueField
# does not have and will hang. The ARM↔BMC channel is ipmb_host.
ls -l /dev/ipmi*                    # expect /dev/ipmi0
lsmod | grep ipmi                   # expect ipmi_devintf + ipmb_host
```

> If `sudo` is slow with `unable to resolve host …local.forge`, add it to
> `/etc/hosts`: `echo "127.0.1.1 $(hostname)" | sudo tee -a /etc/hosts`.

#### Step 2 — Confirm the BMC is alive and read its logs

```bash
sudo ipmitool -N 3 -R 2 mc info     # Mellanox / FW 25.10 etc. = BMC firmware alive
sudo ipmitool sel elist | tail -50  # event log — look for the cause of the wedge
sudo ipmitool lan print 1           # the key diagnostic: IP / source / MAC
```

What to look for in `sel elist`:

- Repeated `System Boot Initiated … warm reset` + `boot_progress` clusters →
  the DPU reboot-looping during a failed `InstallDPUOS`.
- **`Cable / Interconnect p0_link | Config Error | Asserted`** repeating up to
  *now* → a live **physical-layer link/cable fault** on the DPU. If the BMC's
  network rides this path (or its own OOB jack is uncabled), it can never
  DHCP. Check the cable/transceiver before doing anything in software.

> `ipmitool mc selftest` returning `Selftest: not implemented` is **normal** on
> BlueField OpenBMC — it is not a sign of corruption. A healthy `sel info`
> (entries present, low % used) means BMC storage is fine.

#### Step 3 — Factory-reset and cold-reset the BMC

```bash
sudo ipmitool raw 0x32 0x66         # restore BMC factory defaults (DPU BMC)
sudo ipmitool mc reset cold         # reboot the BMC (unreachable ~60–120s)
sleep 120
sudo ipmitool lan print 1
```

After this the BMC reverts to **DHCP**, which is what you want — leave it on
DHCP and let `carbide-dhcp` lease it. Confirm the LAN MAC matches the
`expected_machine` BMC MAC (`…:b1`).

#### Step 4 — (only if DHCP is unavailable) set a static IP — order matters

OpenBMC ties the prefix length to the **address object**, and applies changes
**asynchronously**. Two rules: set the netmask *after* the address exists, and
**do not** `mc reset cold` right after — the reset wipes an uncommitted change.

```bash
sudo ipmitool lan set 1 ipsrc static
sudo ipmitool lan set 1 ipaddr 172.16.0.24      # a FREE underlay IP, NOT the ARM's
sudo ipmitool lan set 1 netmask 255.255.255.0   # re-apply AFTER ipaddr exists
sudo ipmitool lan set 1 defgw ipaddr 172.16.0.1
sleep 10
sudo ipmitool lan print 1                        # verify IP *and* /24 mask stuck
```

> **Pitfalls observed:** (1) setting `netmask` before the address fails with
> `LAN Parameter Data does not match!` and leaves a `/32`; (2) a `mc reset
> cold` immediately after the writes reverts everything except `ipsrc`. If you
> need a reset, do it only after `lan print` confirms the config, and re-verify
> afterwards.

#### Notes on consoles & logs

- **SOL is not the BMC shell.** `ipmitool … sol activate` (and NICo's
  `forge-ssh-console`) redirect the **managed system's** serial console — on a
  DPU that's the ARM OS — and require the BMC reachable over `lanplus`. They
  will not show BMC logs.
- `ncli ssh show-obmc-log <bmc-ip> <user> <pass>` reads the OpenBMC console log
  but needs the BMC **on the network** first — useful only after rediscovery.
- A BMC that's alive in-band but cannot keep network config across a reboot, or
  shows `Default Gateway MAC: 00:00:00:00:00:00` with a correct `/24`, has **no
  L2 carrier** — that's the physical link (`p0_link Config Error`), not software.

#### Step 5 — Re-trigger discovery

```bash
# once the BMC has an IP, clear any stuck preingestion state and let it ingest
kubectl exec -n postgres postgres-0 -- psql -U carbide carbide -c \
  "UPDATE explored_endpoints SET preingestion_state='{\"state\":\"initial\"}'::jsonb \
   WHERE bmc_ip IN ('172.16.0.23','172.16.0.24');"

kubectl logs -n forge-system deployment/carbide-dhcp -f --since=1m | grep -i "84:eb:0c:5b:59:b1"
```

If the BMC now `DHCPDISCOVER`s but allocation still fails, see the next section.

---

### DHCP discovery jammed — fast-path FQDN squat

**Symptom:** the BMC reaches `carbide-dhcp` but never gets a lease:

```text
INFO  LOG_CARBIDE_PKT4_RECEIVE … msg_type=DHCPDISCOVER … type=060 "NVIDIA/BF/BMC" … type=061 01:84:eb:0c:5b:59:b1
… err=unable to create machine interface in fast path out of segments
   [NetworkSegment { … name: "admin" … 172.16.0.0/24 … num_reserved: 20, num_free_ips: 0 }] after 128 retries
```

This persists **even after a full DB purge / redeploy**, and the pool is
clearly not full (only a handful of IPs used).

**Root cause:** `machine_interfaces` carry a `hostname` derived from their IP
(e.g. `172-16-0-20`) and a unique constraint
`fqdn_must_be_unique UNIQUE (domain_id, hostname)`
(`crates/api-db/migrations/20211119192131_initial.sql`). When a lease is
released/invalidated, the **address row is deleted but the interface row (with
its hostname) is left behind** — an *address-less interface* that keeps the
FQDN reserved. The fast-path allocator picks the lowest free address checking
**only `machine_interface_addresses`** (`crates/api-db/src/machine_interface.rs`,
`allocate_next_ip_with_retry`), derives the same hostname, and the insert hits
`fqdn_must_be_unique`. The outer loop retries the **same lowest IP** 128 times
(`create_fast_path` → `is_fqdn_conflict()`), then gives up. One squatting row
on a low IP deadlocks **all** new discovery on that segment.

**Diagnose** (replace the segment id with your `admin`/underlay segment):

```sql
-- interfaces in the segment that have NO address but DO hold a hostname/FQDN:
SELECT mi.id, mi.mac_address, mi.hostname,
       (SELECT count(*) FROM machine_interface_addresses a WHERE a.interface_id = mi.id) AS naddr
FROM machine_interfaces mi
WHERE mi.segment_id = '<ADMIN_SEGMENT_ID>'
ORDER BY mi.hostname;
-- squatters show naddr = 0 with hostnames like 172-16-0-20 / 172-16-0-21
```

**Fix:** delete the address-less, machine-less interface shells:

```sql
BEGIN;
WITH squatters AS (
  SELECT mi.id FROM machine_interfaces mi
  WHERE mi.segment_id = '<ADMIN_SEGMENT_ID>'
    AND mi.machine_id IS NULL
    AND NOT EXISTS (SELECT 1 FROM machine_interface_addresses a WHERE a.interface_id = mi.id)
)
DELETE FROM dhcp_entries WHERE machine_interface_id IN (SELECT id FROM squatters);

DELETE FROM machine_interfaces mi
WHERE mi.segment_id = '<ADMIN_SEGMENT_ID>'
  AND mi.machine_id IS NULL
  AND NOT EXISTS (SELECT 1 FROM machine_interface_addresses a WHERE a.interface_id = mi.id);
COMMIT;
```

Interfaces that still own a valid address (e.g. the live host BMC) are
preserved. After the delete, the BMC's next `DHCPDISCOVER` allocates a free IP,
the hostname insert no longer collides, and `site-explorer` ingests it.

> **Production impact:** this is **not** lab-only. Any lease
> release/invalidation that leaves an address-less interface row will squat its
> FQDN and, once the lowest addresses fill, jam allocation for the whole
> segment. Two upstream fixes are warranted: (1) lease release should delete the
> `machine_interface` row (or null its `hostname`), and (2) the fast-path
> candidate query should also exclude IPs whose derived hostname already exists
> for the segment's `domain_id`. Until then, the cleanup query above is the
> mitigation, and the address-less-interface count is a good thing to alert on.

---

### Useful diagnostic commands

```bash
# Check site explorer report for a specific DPU BMC
ncli site-explorer get-report endpoint <DPU-BMC-IP>

# Re-trigger exploration in the next cycle (address is POSITIONAL, not --address)
ncli site-explorer re-explore <DPU-BMC-IP>

# Clear a stuck error on a BMC endpoint (address is POSITIONAL, not --address)
ncli site-explorer clear-error <DPU-BMC-IP>

# Full cluster health snapshot
kubectl get pods -n forge-system
kubectl get pods -n metallb-system
kubectl get svc -n forge-system | grep LoadBalancer

# Packet-level: confirm DPU DHCP traffic hitting the relay
sudo tcpdump -i <100G-iface> -n port 67 or port 68 -v
```

---

## Site-explorer & expected-machine command reference

These are the commands used to inspect and unstick BMC discovery. Subcommands
are defined in `crates/admin-cli/src/site_explorer/` and
`crates/admin-cli/src/expected_machines/`.

> **Flag gotcha:** `explore`, `re-explore`, `clear-error`, `remediation`, and
> `get-report endpoint|managed-host` take the BMC IP as a **positional**
> argument. Only `delete` uses `--address`. Don't mix them up.

### `ncli site-explorer` — inspect / drive discovery

| Command | What it does |
|---------|--------------|
| `ncli site-explorer get-report all` | Dump the entire latest exploration report as JSON |
| `ncli site-explorer get-report endpoint` | Table of all explored BMC endpoints (add `--erroronly`, `--successonly`, `--unpairedonly`, `-v <vendor>` to filter) |
| `ncli site-explorer get-report endpoint <BMC-IP>` | Detail for one endpoint: type, vendor, machine id, **Preingestion State**, **Last Exploration Error**, report version |
| `ncli site-explorer get-report managed-host [<BMC-IP>]` | Discovered managed-host (host+DPU) view |
| `ncli site-explorer explore <BMC-IP> [--mac <mac>]` | Explore **once now** and print the result — does **not** store it (safe probe) |
| `ncli site-explorer re-explore <BMC-IP> [--mac <mac>]` | Queue the endpoint for the **next** exploration cycle and **store** the result |
| `ncli site-explorer clear-error <BMC-IP> [--mac <mac>]` | Clear the latched `Last Exploration Error` — **required to release `AvoidLockout`** after a credential fix |
| `ncli site-explorer delete --address <BMC-IP>` | Remove the explored endpoint row from the DB entirely (hard reset of that endpoint) |
| `ncli site-explorer remediation <BMC-IP> --pause` / `--resume` | Pause/resume automatic remediation actions for an endpoint |
| `ncli site-explorer have-credentials <...>` | Check whether NICo holds usable BMC credentials for the endpoint |
| `ncli site-explorer is-bmc-in-managed-host <...>` | Check whether a BMC is already part of a managed host |
| `ncli site-explorer copy-bfb-to-dpu-rshim --address <DPU-BMC-IP> --host-bmc-ip <HOST-BMC-IP> [--mac <mac>] [--pre-copy-powercycle]` | BFB recovery push over rshim (see Step 6, Path B) |

### `ncli em` (expected-machine) — what NICo looks for & which creds it uses

| Command | What it does |
|---------|--------------|
| `ncli em show` | Table of all expected machines + their discovered `Interface IP` (`Undiscovered` until the BMC leases) and `Associated Machine` |
| `ncli em show <BMC-MAC>` | Full detail for one expected machine (positional MAC) |
| `ncli em add --bmc-mac-address <mac> --bmc-username <u> --bmc-password <p> --chassis-serial-number <sn>` | Add a new expected machine |
| `ncli em patch --bmc-mac-address <mac> --bmc-username <u> --bmc-password <p>` | **Partial** update — only the fields given change (use this to fix just the password; username+password must be given together) |
| `ncli em patch --bmc-mac-address <mac> ... --bmc-retain-credentials true` | Tell site-explorer **not to rotate** this BMC's password (store the supplied creds as-is in Vault) |
| `ncli em update --filename <file.json>` | Full replacement of **one** machine from JSON |
| `ncli em replace-all --filename <file.json>` | Replace the **entire** expected-machines table (must include every machine, e.g. the host BMC too — it wipes anything not listed) |
| `ncli em delete <...>` / `ncli em erase` | Delete one / erase all expected machines |

### Resetting / unsticking site-explorer for an endpoint

There is no single "reset site-explorer" button — you reset a specific
endpoint. Pick the lightest action that applies:

```bash
# 1) Soft reset — clear the latched error so the next cycle retries.
#    Use this after fixing BMC credentials / reachability (clears AvoidLockout).
ncli site-explorer clear-error 172.16.0.20
ncli site-explorer re-explore 172.16.0.20
ncli site-explorer get-report endpoint 172.16.0.20      # confirm it advances past "Initial"

# 2) Reset the preingestion state machine in the DB (when stuck mid-preingestion):
kubectl exec -n postgres postgres-0 -- psql -U carbide carbide -c \
  "UPDATE explored_endpoints SET preingestion_state='{\"state\":\"initial\"}'::jsonb \
   WHERE bmc_ip = '172.16.0.20';"

# 3) Hard reset — delete the explored endpoint entirely and let it be
#    rediscovered from scratch on the next DHCP/scan cycle:
ncli site-explorer delete --address 172.16.0.20

# 4) Pause/resume remediation (e.g. to stop auto power-cycles while you debug):
ncli site-explorer remediation 172.16.0.20 --pause
ncli site-explorer remediation 172.16.0.20 --resume
```

> `clear-error` only resets the *error*; if the underlying cause (wrong
> password, unreachable BMC) is still present, the next exploration re-latches
> it. Always fix the root cause **first**, then `clear-error` + `re-explore`.

---

## Production hardening

Lessons from lab bring-up that change how you should run this in production.

### Firmware version handling in production

Two independent version surfaces must stay consistent, or you get either
`INVALID FW PACKAGE` (download-time rejection) or an endless reflash/power-cycle
churn (run-time autoupdate):

**1. BFB DOCA generation ↔ BMC firmware generation.**
The DPU BMC validates the BFB before accepting it. The `forge.bfb` you serve
**must** be built from a DOCA generation compatible with the BMC's firmware
generation. In this lab the BMC matched **`BF-25.10-15`** (a BF-25.x BMC), which
requires a **DOCA 2.9.2** BFB — see the
[Firmware → DOCA compatibility table](#invalid-fw-package--bfbmmc-version-mismatch).
In production:

- Pin `DOCA_VERSION`/`BFB_BUILD`/`BFB_RELEASE`/`DOCA_HBN_TAG` in
  `pxe/Makefile.toml` to the validated combo for your fleet's BMC generation,
  and rebuild `forge.bfb` whenever you intentionally move BMC generations.
- Read the BMC generation per host before flashing:
  `curl -sk -u root:'<pass>' https://<DPU_BMC_IP>/redfish/v1/Managers/Bluefield_BMC/ | jq .FirmwareVersion`.
- If you run a mixed fleet (BF-24/25/32), keep one `forge.bfb` per generation
  and select by BMC version — do **not** assume one BFB fits all.

**2. Component `known_firmware` ↔ what the BFB actually flashes.**
The site config declares expected component versions and turns on autoupdate:

```29:29:dev/deployment/devspace/values.base.yaml
        { version = "BF-25.10-15", default = true },
```
```40:42:dev/deployment/devspace/values.base.yaml
      known_firmware = [
        { version = "32.47.1088", default = true },
      ]
```

with `firmware_global.autoupdate = true`. NICo compares each component's
**reported** version (BMC, CEC, NIC, UEFI) against the `default = true`
`known_firmware` entry; any mismatch triggers a firmware update — which itself
needs a power-cycle to activate. So:

- **Make the declared `default` versions match what your `forge.bfb`/DOCA bundle
  actually lands.** E.g. if the bundle flashes NIC `32.47.1000` but the config
  says `32.47.1088`, autoupdate will keep trying to re-flash to `1088` (each
  attempt needing a power-cycle) — a churn loop. Keep the two in lock-step.
- Treat `known_firmware` as your **validated allow-list**: bump it deliberately,
  together with the BFB, after qualifying a new firmware bundle — not ad hoc.
- After provisioning, confirm reconciliation with `ncli dpu versions` (expected
  == current for all components) before declaring a node healthy. A node whose
  versions never converge is usually a flash that wasn't activated — see
  [§ flint FwInit has failed](#flint-fwinit-has-failed--wedged-nic-firmware-cold-power-cycle-required)
  (cold power-cycle), not a config problem.

> **Key takeaway:** a firmware *flash* is not complete until a **cold
> power-cycle** activates it. In the automated flow NICo does this via
> `WaitingForPlatformPowercycle`; don't bypass it with manual DB edits, and
> don't expect an Arm `reboot` to substitute for it.

### Replacing the bundled `unbound` with site/external DNS

`unbound` (the `.forge` resolver) is the batteries-included default so a
greenfield site works out of the box. In production you can use your **existing
site/external DNS** instead — nothing in NICo requires *unbound* specifically,
only that **some** resolver on the OOB network answers the `.forge` names. To
switch:

1. Point DHCP at your resolver — set `carbide-nameservers` (the `carbide-dhcp`
   `keaConfigJson` hook param) to your DNS server IP instead of the unbound VIP.
2. Add the `.forge` A-records to that server, matching your VIPs:
   - `carbide-api.forge` → carbide-api external VIP (`172.16.0.89`)
   - `carbide-pxe.forge` → carbide-pxe VIP (`172.16.0.86`)
   - `carbide-static-pxe.forge` → carbide-pxe VIP (`172.16.0.86`)
   - `carbide-ntp.forge` → NTP VIP (`172.16.0.80`)
3. Ensure it can recurse/forward for non-`.forge` names the DPU/BMC need
   (NTP, registries, telemetry).
4. Set `unbound.enabled: false`.

> **Why not just use `carbide-dns`?** It's an API-driven authoritative server
> for tenant/VPC records and is **not** a recursive resolver nor authoritative
> for the static `.forge` zone — see
> [§ Why a dedicated unbound](#why-a-dedicated-unbound-instead-of-reusing-carbide-dns).
> Use unbound **or** your own DNS; `carbide-dns` is neither.

> **Renewal caveat (the `.90`/`.91` trap):** whatever IP you advertise via
> `carbide-nameservers` only takes effect for a BMC on its **next DHCP
> renewal**. If you move the resolver IP (or a MetalLB VIP lands on a different
> address than configured), already-leased BMCs keep the old resolver and DNS
> silently breaks mid-provision. After changing it, force a DHCP renewal (BMC
> cold reset) or patch `StaticNameServers` via Redfish on leased BMCs, and
> confirm the running VIP matches what DHCP advertises
> (`kubectl get svc -n forge-system | grep -E 'unbound|dns'`).

---

## Sample Log Outputs

### carbide-dhcp — healthy DHCP relay (test script)

When running `dhcp_relay_test.py` against a test MAC (not in `expected_machines.json`):

```
2026-05-14 06:11:28.287 INFO  [kea-dhcp4.carbide-callouts/...] LOG_CARBIDE_PKT4_RECEIVE: Packet type name: DHCPDISCOVER
2026-05-14 06:11:28.287 ERROR [kea-dhcp4.carbide-callouts/...] LOG_CARBIDE_PKT4_RECEIVE: Missing option [60] in packet
2026-05-14 06:11:28.287 ERROR [kea-dhcp4.carbide-callouts/...] LOG_CARBIDE_PKT4_RECEIVE: Missing option [93] in packet
2026-05-14 06:11:28.397 INFO  [kea-dhcp4.leases/...]           DHCP4_LEASE_ADVERT [hwtype=1 50:6b:8d:a3:05:39], cid=[no info], tid=0xb6f53b49: lease 0.0.0.5 will be advertised
2026-05-14 06:11:28.397 INFO  [kea-dhcp4.carbide-callouts/...] LOG_CARBIDE_PKT4_SEND ... msg_type=DHCPOFFER (2), remote_address=172.16.0.121:67
```

**What each line means:**

| Line | Meaning | Action needed? |
|------|---------|----------------|
| `Packet type name: DHCPDISCOVER` | Relay packet accepted (`giaddr` non-zero) | None ✓ |
| `Missing option [60]` | Vendor Class Identifier absent — test script only | None — benign ✓ |
| `Missing option [93]` | Client System Architecture absent — test script only | None — benign ✓ |
| `lease 0.0.0.5 will be advertised` | Placeholder IP — MAC not in `expected_machines.json` | Register MAC to get real IP |
| `DHCPOFFER ... remote_address=giaddr:67` | OFFER unicast back to relay agent — relay working | None ✓ |

### carbide-dhcp — healthy DHCP relay (real BMC)

When a real registered BMC PXE-boots (options [60] and [93] present):

```
INFO  LOG_CARBIDE_PKT4_RECEIVE: Packet type name: DHCPDISCOVER
INFO  LOG_CARBIDE_PKT4_RECEIVE: vendor_class=PXEClient:Arch:00007:UNDI:003016
INFO  DHCP4_LEASE_ADVERT [hwtype=1 aa:bb:cc:dd:ee:01] ... lease 172.16.0.20 will be advertised
INFO  LOG_CARBIDE_PKT4_SEND ... msg_type=DHCPOFFER (2) ...
INFO  LOG_CARBIDE_PKT4_RECEIVE: Packet type name: DHCPREQUEST
INFO  DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:01] ... lease 172.16.0.20 has been allocated
INFO  LOG_CARBIDE_PKT4_SEND ... msg_type=DHCPACK (5) ...
```

The full 4-step handshake (DISCOVER → OFFER → REQUEST → ACK) only happens with a
real DHCP client. The test script only exercises DISCOVER → OFFER and is sufficient
to verify relay connectivity.

### carbide-dhcp — relay packet dropped (wrong giaddr)

If `dhcping` or `dhclient` is used directly (no relay agent, `giaddr = 0.0.0.0`):

```
INFO  LOG_CARBIDE_PKT4_RECEIVE Carbide hook called ... remote_address=172.16.0.121:142
ERROR LOG_CARBIDE_PKT4_RECEIVE Carbide hook called ... Received a non-relayed packet, dropping it
```

**Fix:** Use `dhcp_relay_test.py` instead — it sets `giaddr` correctly.

### carbide-api — network segment not found

If the `admin` network segment prefix is stale or missing:

```
ERROR msg="Internal error: No network segment defined for relay addresses: [172.16.0.121]"
      location="crates/api/src/errors.rs:358"
```

**Fix:** See [`DEBUG.md § DHCP Relay Fails`](DEBUG.md#dhcp-relay-fails--no-network-segment-defined-for-relay-address) —
delete the stale segment from PostgreSQL and restart `carbide-api`.


### carbide-dhcp — DHCP relay working, network segment OK

Expected carbide-dhcp log when relay is fully healthy (OFFER sent successfully):

```
INFO  LOG_CARBIDE_PKT4_SEND Carbide hook called for DHCPv4 packet send
      local_address=10.244.252.144:67, remote_address=172.16.0.121:67,
      msg_type=DHCPOFFER (2), transid=0xb6f53b49,
      options:
        type=001, len=004: 4294967040        ← subnet mask 255.255.255.0
        type=003, len=004: 172.16.0.1        ← gateway
        type=006, len=004: 127.0.0.1         ← DNS (carbide-dns in prod)
        type=053, len=001: 2                 ← DHCP message type: OFFER
        type=054, len=004: 10.244.252.144    ← server identifier (pod IP)
        type=051, len=004: 3600              ← lease time 1h
```

`remote_address=172.16.0.121:67` confirms the OFFER was unicast to the relay agent
on port 67 (RFC 2131 §4.1 behavior). The test host receives it via its UDP socket
bound to port 67.
