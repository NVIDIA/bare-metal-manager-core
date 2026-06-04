# NuraMetal Lab — kubeadm + DevSpace + NICo Deployment Guide

> **Lab network diagram:** `canvas/nurametal-lab-network.html`

---

## Network Change Notice

> **As of this revision, the `10.17.48.x` management network no longer exists.**
> All VM management traffic now runs over the **10G network (`172.16.0.x/24`)**.
>
> **Access to the cluster:** SSH to the jump host **`10.17.48.50`** (`root` / `nutanix/4u`),
> then SSH from there to the VMs on their `172.16.0.x` addresses.

---

## IP Reservation Table

The following IPs **must be reserved** in the `172.16.0.0/24` network
(i.e., excluded from any DHCP pool and not assigned to bare-metal nodes):

| IP Address | Purpose |
|---|---|
| `172.16.0.77` | Reserved — infrastructure |
| `172.16.0.78` | Reserved — infrastructure |
| `172.16.0.79` | Reserved — infrastructure |
| `172.16.0.80` | `nico-cp-1` — eth0 (10G / VM management + kubeadm API) |
| `172.16.0.81` | `nico-worker-1` — eth0 (10G / VM management) |
| `172.16.0.82` | `nico-worker-2` — eth0 (10G / VM management) |
| `172.16.0.83` | Reserved — spare worker or future VM |
| `172.16.0.84` | Reserved — spare worker or future VM |
| `172.16.0.85` | MetalLB VIP — `carbide-dhcp` (DHCP relay target, UDP 67) |
| `172.16.0.86` | MetalLB VIP — `carbide-pxe` (PXE next-server, TCP 80) |
| `172.16.0.87` | MetalLB VIP — `carbide-dns-0` (DNS replica 0, UDP/TCP 53) |
| `172.16.0.88` | MetalLB VIP — `carbide-dns-1` (DNS replica 1, UDP/TCP 53) |
| `172.16.0.89` | MetalLB VIP — `carbide-api` (Scout / admin CLI, TCP 443) |
| `172.16.0.90` | MetalLB VIP — `carbide-ssh-console` (SSH serial, TCP 22) |
| `172.16.0.91` | MetalLB VIP — `forge-unbound` (`.forge` zone resolver, UDP/TCP 53) |
| `172.16.0.92` | MetalLB VIP — reserved for future NICo service |
| `172.16.0.93` | MetalLB VIP — reserved for future NICo service |
| `172.16.0.94` | MetalLB VIP — reserved for future NICo service |
| `172.16.0.95` | MetalLB VIP — reserved for future NICo service |
| `172.16.0.96` | Reserved — infrastructure |
| `172.16.0.97` | Reserved — infrastructure |
| `172.16.0.98` | Reserved — infrastructure |
| `172.16.0.99` | Reserved — infrastructure |
| `172.16.0.100` | NICo loopback IP pool start (allocated to bare-metal hosts) |
| `172.16.0.101` | NICo loopback IP pool |
| `172.16.0.102` | NICo loopback IP pool |
| `172.16.0.103` | NICo loopback IP pool |
| `172.16.0.104` | NICo loopback IP pool |
| `172.16.0.105` | NICo loopback IP pool |
| `172.16.0.106` | NICo loopback IP pool |
| `172.16.0.107` | NICo loopback IP pool |
| `172.16.0.108` | NICo loopback IP pool |
| `172.16.0.109` | NICo loopback IP pool |
| `172.16.0.110` | NICo loopback IP pool |
| `172.16.0.111` | NICo loopback IP pool |
| `172.16.0.112` | NICo loopback IP pool |
| `172.16.0.113` | NICo loopback IP pool |
| `172.16.0.114` | NICo loopback IP pool |
| `172.16.0.115` | NICo loopback IP pool |
| `172.16.0.116` | NICo loopback IP pool |
| `172.16.0.117` | NICo loopback IP pool |
| `172.16.0.118` | NICo loopback IP pool |
| `172.16.0.119` | NICo loopback IP pool |
| `172.16.0.120` | NICo loopback IP pool |
| `172.16.0.121` | NICo loopback IP pool end |

> **DHCP pool for bare-metal BMC boot:** `172.16.0.20 – 172.16.0.76`.
> Controlled by `reserve_first = 20` in `[networks.admin]` of `values.base.yaml` —
> this reserves `.0–.19` so carbide-api starts allocating from `.20`.
> There is no hard upper bound; `.77` upward is reserved by convention for static
> assignments (VM NICs, MetalLB VIPs) which must never be handed out via DHCP.
> If you change `reserve_first`, delete the stale `admin` segment from the DB and
> restart `carbide-api` — see [DEBUG.md § Stale Network Segment](DEBUG.md#dhcp-relay-fails--no-network-segment-defined-for-relay-address).

---

## Diagram 1 — Nutanix AHV Network Configuration Flow

```mermaid
flowchart TD
    subgraph PE["🖥️ Nutanix Prism Element (PE/CVM) — AHV Configuration"]
        direction TB
        P1["Prism Element → VMs\nSelect Ubuntu VM → Update"]
        P2["Network Adapters → NIC 1 (eth0)\nAssign static IP from 10G network\n172.16.0.80 / .81 / .82\n(management + kubeadm API server)"]
        P4["Virtual Switches → 10G vSwitch\nSecurity → Allow MAC address changes\n✅ Forged Transmits (for MetalLB ARP)"]
        P5["acli net.update <10g-net>\nip_config.allow_ip_override=true"]
        P6["Power Cycle VM\nNIC appears in OS"]

        P1 --> P2 --> P6
        P2 --> P4 --> P5
        P5 --> P6
    end

    subgraph JUMP["🔀 Jump Host Access"]
        direction TB
        J1["SSH to Jump Host\n10.17.48.50\nroot / nutanix/4u"]
        J2["From jump host, SSH to VMs\nnico-cp-1: 172.16.0.80\nnico-worker-1: 172.16.0.81"]
        J1 --> J2
    end

    subgraph STATICIP["🌐 Ubuntu VM — Static IP Configuration"]
        direction TB
        S1["Identify interfaces\nip link show\neth0 = 10G network (172.16.0.x)"]
        S2["Configure eth0 static IP\n/etc/netplan/50-10g.yaml\n172.16.0.80/24 (VM1)\n172.16.0.81/24 (VM2)"]
        S4["sudo netplan apply\nVerify IP + routes"]

        S1 --> S2 --> S4
    end

    subgraph METALLB["⚖️ MetalLB L2 Advertisement"]
        direction TB
        M1["IPAddressPool\n172.16.0.85 – 172.16.0.95\n(reserved range, above DHCP ceiling .60)"]
        M2["L2Advertisement\ninterfaces: [eth0]\n← pins to 10G NIC (management + BMC OOB)"]
        M3["MetalLB speaker sends ARP/GARP\nfor VIPs on 172.16.0.0/24 via eth0"]
        M4["OOB Switch sees VIPs\n172.16.0.85–.95 reachable ✅\nDHCP relay can reach 172.16.0.85"]

        M1 --> M2 --> M3 --> M4
    end

    subgraph VERIFY["✅ Verification"]
        direction TB
        VR1["arping -I eth0 172.16.0.85\n→ reply from MetalLB speaker MAC"]
        VR2["kubectl get svc -n forge-system\n→ carbide-dhcp EXTERNAL-IP 172.16.0.85 ✅"]
        VR3["kubectl get pods -n metallb-system\n→ controller + speakers Running ✅"]

        VR1 --> VR2 --> VR3
    end

    JUMP      -->|"reach VMs via jump host"| STATICIP
    STATICIP  -->|"eth0: 172.16.0.8x"| METALLB
    METALLB   -->|"VIPs advertised on 10G network"| VERIFY

    style PE       fill:#0f1e35,stroke:#38bdf8,color:#e2e8f0
    style JUMP     fill:#1a0f35,stroke:#a78bfa,color:#e2e8f0
    style STATICIP fill:#0f1e10,stroke:#4ade80,color:#e2e8f0
    style METALLB  fill:#1c1005,stroke:#facc15,color:#e2e8f0
    style VERIFY   fill:#0f1a0f,stroke:#34d399,color:#e2e8f0
```

---

## Diagram 2 — Kubernetes + NICo Full Configuration Flow

```mermaid
flowchart TD
    subgraph PRE["Phase 0–1: Prerequisites (Prism PE + Ubuntu VMs)"]
        direction LR
        A1["Jump Host: 10.17.48.50\nroot/nutanix/4u\n→ SSH to VMs"]
        A2["Prism PE: Add 10G NIC (eth0)\nstatic IP 172.16.0.80/.81/.82\nmanagement + kubeadm API server"]
        A4["Prism PE: Enable\nForged Transmits\non 10G vSwitch"]
        A5["Each VM: disable swap\nkernel params\nbr_netfilter + ip_forward"]
        A6["Each VM: install\ncontainerd\nkubeadm kubelet kubectl"]
        A1 --> A2
        A2 --> A5
        A4 --> A5
        A5 --> A6
    end

    subgraph K8S["Phase 2: kubeadm Cluster"]
        direction TB
        B1["VM1 (172.16.0.80)\nkubeadm init\n--apiserver-advertise-address\n=172.16.0.80"]
        B2["kubectl apply\nCalico CNI v3.28.1"]
        B3["VM2 + VMN\nkubeadm join\n172.16.0.80:6443"]
        B4["kubectl get nodes\n→ all Ready ✅"]
        B5["kubeconfig ready\non nico-cp-1 172.16.0.80\n(~/.kube/config)"]

        B1 --> B2 --> B3 --> B4 --> B5
    end

    subgraph MLB["Phase 4: MetalLB"]
        direction TB
        C1["helm install metallb v0.14.5"]
        C2["IPAddressPool\n172.16.0.85–.95"]
        C3["L2Advertisement\ninterfaces: [eth0]"]
        C4["kubectl get ipaddresspool ✅"]

        C1 --> C2 --> C3 --> C4
    end

    subgraph TOOLS["Phase 3: Dev Tools (nico-cp-1 172.16.0.80)"]
        direction LR
        T1["helm\nhelmfile\nhelm-diff"]
        T2["devspace CLI"]
        T3["Docker\n(image builds)"]
        T4["kubectl\n+ KUBECONFIG from VM1"]
        T1 --- T2 --- T3 --- T4
    end

    subgraph CFG["Phase 5: NICo Configuration"]
        direction TB
        D1["helm-prereqs/values.yaml\nsiteName: nurametal-lab"]
        D2["metallb-config.yaml\nVIP pool 172.16.0.85–.95\nL2 via eth0"]
        D3["ncx-core.yaml\ncarbide-api hostname\ndhcp_servers=[172.16.0.85]\nnetworks.admin: 172.16.0.0/24\nMetalLB VIP per service"]
        D4["values.base.yaml\nenable: dhcp pxe dns bmc-proxy\ndisable: machine-a-tron mock\ndpu_ipmi_tool_impl=ipmi"]

        D1 --> D2 --> D3 --> D4
    end

    subgraph BOOT["Phase 6–7: Bootstrap + DevSpace Deploy"]
        direction TB
        E1["kubectl apply\nlocal-path-provisioner\nstorageclass"]
        E2["bootstrap-prereqs.sh\n→ cert-manager + Vault + Postgres"]
        E3["devspace deploy -n forge-system\n(~30–45 min first Rust build)"]
        E4["kubectl get svc -n forge-system\n→ all VIPs assigned ✅"]

        E1 --> E2 --> E3 --> E4
    end

    subgraph SW["Phase 8: OOB Switch DHCP Relay"]
        direction TB
        F1["10G Switch — VLAN 101\ninterface Vlan101\nip helper-address 172.16.0.85"]
        F3["Verify:\nkubectl logs carbide-dhcp\n→ DISCOVER / OFFER / ACK ✅"]

        F1 --> F3
    end

    subgraph REG["Phase 9: Register Machines"]
        direction TB
        G1["cargo build -p carbide-admin-cli"]
        G2["ncli credential add-bmc\n--kind=site-wide-root\n--password=new-pwd"]
        G3["expected_machines.json\nbmc_mac / bmc_username\nbmc_password / serial_number"]
        G4["ncli em replace-all\n--filename expected_machines.json"]
        G5["ncli mb site trusted-machine\napprove * persist\n--pcr-registers=0,3,5,6"]

        G1 --> G2 --> G3 --> G4 --> G5
    end

    subgraph PXEFLOW["Phase 9e–10: PXE Boot + Discovery"]
        direction TB
        H1["Power on SUT/SUD Server"]
        H2["BMC → DHCP Discover\nVLAN 101 via 10G Switch"]
        H3["carbide-dhcp 172.16.0.85\n→ gRPC → carbide-api\n→ allocates 172.16.0.20–.60"]
        H4["DHCP Offer\nnext-server=172.16.0.86"]
        H5["Host PXE boots\niPXE from carbide-pxe :80"]
        H6["Scout OS boots\nScout agent → mTLS/gRPC\n→ carbide-api:443\nreports hardware inventory"]
        H7["DPU BMC → DHCP VLAN 101\n→ site-explorer Redfish\n→ DPU Agent → HBN config"]
        H8["State machine\nDiscovering → Inventoried\n→ Validated → Ready ✅"]

        H1 --> H2 --> H3 --> H4 --> H5 --> H6
        H6 --> H7
        H6 --> H8
        H7 --> H8
    end

    PRE   -->|"all VMs ready"| K8S
    K8S   -->|"cluster up"| TOOLS
    K8S   -->|"cluster up"| MLB
    TOOLS -->|"devspace + kubectl ready"| CFG
    MLB   -->|"VIP pool ready"| CFG
    CFG   -->|"values files written"| BOOT
    BOOT  -->|"forge-system Running + VIPs"| SW
    BOOT  -->|"forge-system Running"| REG
    SW    -->|"relay active"| PXEFLOW
    REG   -->|"machines registered"| PXEFLOW

    style PRE      fill:#0d1424,stroke:#38bdf8,color:#cbd5e1
    style K8S      fill:#0d1424,stroke:#38bdf8,color:#cbd5e1
    style MLB      fill:#12180a,stroke:#facc15,color:#cbd5e1
    style TOOLS    fill:#0d1424,stroke:#a78bfa,color:#cbd5e1
    style CFG      fill:#1a0d05,stroke:#fb923c,color:#cbd5e1
    style BOOT     fill:#0d1424,stroke:#38bdf8,color:#cbd5e1
    style SW       fill:#1a0d05,stroke:#fb923c,color:#cbd5e1
    style REG      fill:#0d1424,stroke:#f87171,color:#cbd5e1
    style PXEFLOW  fill:#060e0c,stroke:#34d399,color:#cbd5e1
```

---

## Network Reference

### Access Path

```
Your Laptop
    │
    ▼  SSH
Jump Host: 10.17.48.50  (root / nutanix/4u)
    │
    ▼  SSH
nico-cp-1:    172.16.0.80   (kubeadm control-plane, all kubectl/devspace runs here)
nico-worker-1: 172.16.0.81
nico-worker-2: 172.16.0.82
```

```bash
# From your laptop:
ssh root@10.17.48.50          # jump host

# From jump host to cluster VMs:
ssh root@172.16.0.80        # nico-cp-1  (control-plane)
ssh root@172.16.0.81        # nico-worker-1
ssh root@172.16.0.82        # nico-worker-2

# Or use ProxyJump from your laptop directly:
ssh -J root@10.17.48.50 root@172.16.0.80
```

### Switch Topology

```
┌─────────────────────────────────────────────────────────────────────┐
│  Nutanix AHV Host fabric (physical hypervisor NICs only)            │
│                                                                     │
│   ┌──────────────────────┐   ┌──────────────────────┐              │
│   │  Nutanix AHV Host 1  │   │  Nutanix AHV Host 2  │  ...         │
│   └──────────┬───────────┘   └──────────┬───────────┘              │
│              │                          │                           │
│   ┌──────────┴──────────────────────────┴───────────┐              │
│   │      TOR Switch — AHV cluster fabric             │              │
│   └─────────┬───────────────────────────────────────┘              │
└─────────────│───────────────────────────────────────────────────────┘
              │
   ┌──────────┴──────────────────────────────────────────────────────┐
   │  Jump Host: 10.17.48.50   (root / nutanix/4u)                   │
   │  Entry point into cluster network                               │
   └─────────────────────────────────────────────────────────────────┘
              │
   ┌──────────────────────────────────────────────────────────────────┐
   │  10G Switch(es)                                                  │
   │  VLAN 101  172.16.0.0/24                                         │
   │  VM management + BMC OOB + DPU BMC OOB                          │
   │  DHCP pool .20–.60 — both Host BMC and DPU BMC                  │
   │  ip helper-address → 172.16.0.85 (carbide-dhcp)                 │
   └──────────┬───────────────────────────────────────────────────────┘
              │
   ┌──────────┴───────────────────────────────────────────────────────┐
   │  Ubuntu VMs (nico-cp-1, nico-worker-1, nico-worker-2)            │
   │  eth0 → 10G Switch (172.16.0.80/.81/.82) — mgmt + kubeadm       │
   ├──────────────────────────────────────────────────────────────────┤
   │  SUT/SUD Server 1…N  (bare-metal machines under test)            │
   │  Host BMC NIC → 10G Switch (VLAN 101) — DHCP .20–.60            │
   │  DPU BMC NIC  → 10G Switch (VLAN 101) — DHCP .20–.60            │
   └──────────────────────────────────────────────────────────────────┘
```

### Network CIDRs

| Network | Switch | CIDR | Role |
|---|---|---|---|
| 10G Network | 10G Switch | `172.16.0.0/24` | VM management (eth0) · Host BMC OOB · DPU BMC OOB · DHCP `.20–.60` · Static `.77–.121` · MetalLB VIPs `.85–.95` |
| Jump Host | IT Network | `10.17.48.50/24` | SSH entry point into cluster — no other `10.17.xx` addresses used |

> **The `10.17.48.x` network no longer provides VM management IPs.**
> The only `10.17.48.x` address in use is the **jump host `10.17.48.50`**.
> All VMs, kubeadm, kubectl, and DevSpace run exclusively on `172.16.0.x`.

**Ubuntu VM IPs — hosted on Nutanix PE (CVM), one vNIC per VM:**

| VM | eth0 — 10G (mgmt + kubeadm) | Role |
|---|---|---|
| Ubuntu VM 1 (`nico-cp-1`) | `172.16.0.80/24` | kubeadm control-plane · dev tools |
| Ubuntu VM 2 (`nico-worker-1`) | `172.16.0.81/24` | kubeadm worker |
| Ubuntu VM 3 (`nico-worker-2`) | `172.16.0.82/24` | kubeadm worker |

> **`nico-cp-1` (`172.16.0.80`) is the working machine.** All `kubectl`, `helm`,
> `devspace`, and `carbide-admin-cli` commands run directly on it. Access via jump host.
>
> **Gateway:** `172.16.0.1` (10G Switch L3 interface on VLAN 101).

**MetalLB VIPs — 10G Switch (BMC OOB) only:**

| Service | VIP | Port | Consumer |
|---|---|---|---|
| carbide-dhcp | `172.16.0.85` | 67/UDP | 10G Switch `ip helper-address` — BMC DHCP only |
| carbide-pxe | `172.16.0.86` | 80/TCP | DHCP `next-server` for PXE boot |
| carbide-dns-0 | `172.16.0.87` | 53/UDP+TCP | Managed host DNS |
| carbide-dns-1 | `172.16.0.88` | 53/UDP+TCP | Managed host DNS (replica) |
| carbide-api | `172.16.0.89` | 443/TCP | Scout agent · admin CLI · DevSpace |
| carbide-ssh-console | `172.16.0.90` | 22/TCP | SSH serial console to BMCs |
| forge-unbound | `172.16.0.91` | 53/UDP+TCP | `.forge` zone resolver — DPU/host BMCs during Redfish BFB install; advertised by carbide-dhcp as `carbide-nameservers` |

> **DHCP relay — 10G Switch only:**
> - 10G Switch (VLAN 101 interface): `ip helper-address 172.16.0.85`
> - Both Host BMC and DPU BMC NICs are on VLAN 101 and receive IPs from carbide-dhcp.

---

## Phase 0 — Nutanix Prism Element (PE) Prerequisites

> These steps are performed in **Prism Element** on the CVM.
> After Prism configuration, access VMs via **jump host `10.17.48.50`**.

### 0a. Assign 10G Static IP to each VM (management NIC — eth0)

Each Ubuntu VM's first NIC connects to the **10G network (`172.16.0.0/24`)**.
This is now the management plane — used for SSH (via jump host), kubectl,
DevSpace, and kubeadm API server access.

```
Prism Element → VMs → Select Ubuntu VM → Update
  → Network Adapters → NIC 1 (eth0)
  → Network: <select 10G / VLAN 101 network>
  → IP Assignment: Static
  → IP Address:
      VM1 nico-cp-1     (control-plane): 172.16.0.80
      VM2 nico-worker-1 (worker):        172.16.0.81
      VM3 nico-worker-2 (worker):        172.16.0.82
  → Save
```

> These IPs are in the reserved range (`.77–.95`) — they will not be assigned
> to bare-metal nodes by NICo's DHCP pool (`.20–.60`).

### 0b. Enable Forged Transmits on the 10G vSwitch

MetalLB L2 mode sends ARP/GARP packets with a virtual MAC (the VIP's MAC).
AHV drops these by default. Enable on the 10G vSwitch.

**Via Prism Element UI:**

```
Prism Element → Network → Virtual Switches
  → Select the vSwitch for VLAN 101  (10G Switch / BMC OOB)
  → Security Settings:
      ✅ Allow MAC address changes
      ✅ Forged Transmits
  → Save
```

**Or via `acli` SSH'd into the CVM:**

```bash
# List all networks to find the VLAN 101 network name
acli net.list

# Enable IP override on VLAN 101 (10G / BMC + DPU BMC OOB)
acli net.update <vlan101-network-name> ip_config.allow_ip_override=true

# Verify
acli net.get <vlan101-network-name> | grep allow_ip_override
# allow_ip_override: true
```

### 0d. Access Ubuntu VM via Prism Console and Assign Static IPs

Since the VM has no IP yet (first boot), use the **Prism Element VM console**
to log in and assign static IPs directly from inside the VM.

#### Step 1 — Open VM Console in Prism

```
Prism Element → VMs → Table view
  → Select Ubuntu VM → Actions → Launch Console
  → A noVNC browser console window opens
  → Log in with Ubuntu credentials (default: ubuntu / ubuntu, or as set at install)
```

#### Step 2 — Identify network interface and rename to `eth0`

AHV Ubuntu VMs enumerate NICs with kernel-assigned names that differ per node
(e.g. `ens5` on the control-plane, `ens4` on workers).
This inconsistency breaks MetalLB's `interfaces:` binding and any scripts that
assume a uniform name. Fix this **once per VM** using a `udev` rule pinned to
the NIC's MAC address — the name becomes stable across reboots.

**Observed interface names from `ip link show`:**

| VM | 10G NIC (→ eth0) | MAC |
|---|---|---|
| `nico-cp-1` | `ens5` | `50:6b:8d:c6:84:55` |
| `nico-worker-1` | `ens4` | `50:6b:8d:97:f2:46` |
| `nico-worker-2` | *(check `ip link show`)* | *(record MAC)* |

##### Step 2a — Get the current interface names and MACs (on each VM)

```bash
ip link show
# Record: which interface carries 172.16.0.x (10G)
# If IPs are not yet assigned, identify by MAC or order of appearance

# Quick way to see name + MAC together:
ip -o link show | awk '{print $2, $17}'
# ens5: 50:6b:8d:c6:84:55   ← 10G NIC on nico-cp-1
```

##### Step 2b — Create udev rename rules (on each VM, using its own MACs)

This pins `eth0` to the 10G NIC MAC permanently.

```bash
# --- On nico-cp-1 (substitute MACs from ip link show output) ---
sudo tee /etc/udev/rules.d/10-nico-net.rules <<'EOF'
# 10G NIC (172.16.0.x — management + BMC OOB + DPU BMC OOB) → eth0
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="50:6b:8d:c6:84:55", NAME="eth0"
EOF

# --- On nico-worker-1 ---
sudo tee /etc/udev/rules.d/10-nico-net.rules <<'EOF'
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="50:6b:8d:97:f2:46", NAME="eth0"
EOF

# --- On nico-worker-2 (replace MAC with actual value from ip link show) ---
sudo tee /etc/udev/rules.d/10-nico-net.rules <<'EOF'
SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="<10g-mac>", NAME="eth0"
EOF
```

##### Step 2c — Also disable systemd-networkd predictable naming (belt-and-suspenders)

```bash
# Disable the predictable naming policy so udev rename wins cleanly
sudo ln -sf /dev/null /etc/systemd/network/99-default.link 2>/dev/null || true

# Alternatively, pass net.ifnames=0 biosdevname=0 via GRUB (older Ubuntu):
sudo sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="net.ifnames=0 biosdevname=0"/' \
  /etc/default/grub
sudo update-grub
```

##### Step 2d — Reboot and verify

```bash
sudo reboot
# After reboot, reconnect via jump host:
# ssh -J root@10.17.48.50 root@172.16.0.80   (nico-cp-1 — if already has an IP)
# or use Prism console if this is first-time IP assignment

ip link show
# 3: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ...   ← 10G NIC ✅

# Confirm MAC matches expected:
ip link show eth0 | grep link/ether   # should show 10G MAC
```

> From this point on, **all netplan configs, MetalLB `interfaces:`, and `arping`
> commands use `eth0` (10G) consistently across all VMs.**

#### Step 3 — Disable cloud-init network management

```bash
sudo bash -c 'echo "network: {config: disabled}" \
  > /etc/cloud/cloud.cfg.d/99-disable-network.cfg'
```

#### Step 4 — Assign static IP on `eth0` (10G / management NIC)

> **Prerequisite:** Step 2 udev rename must be done and the VM rebooted so the
> interface is already named `eth0`. All VMs use the same name from here on.

```bash
# Back up any existing netplan config
ls /etc/netplan/
sudo cp /etc/netplan/*.yaml /tmp/ 2>/dev/null || true

# Remove any existing cloud-init generated config that references old names
sudo rm -f /etc/netplan/50-cloud-init.yaml

# --- Ubuntu VM 1 (control-plane, nico-cp-1) ---
sudo tee /etc/netplan/50-10g.yaml <<'EOF'
network:
  version: 2
  ethernets:
    eth0:               # 10G NIC — renamed via udev (was ens5 on cp, ens4 on workers)
      dhcp4: false
      addresses:
        - 172.16.0.80/24    # VM1:.80  VM2:.81  VM3:.82
      routes:
        - to: default
          via: 172.16.0.1   # 10G Switch L3 gateway (VLAN 101)
      nameservers:
        addresses: [127.0.0.53]   # loopback — 8.8.8.8 is unreachable from air-gapped 172.16.0.x
EOF
sudo chmod 600 /etc/netplan/50-10g.yaml
sudo netplan apply

# Verify
ip addr show eth0
ping -c2 172.16.0.1     # gateway reachable
```

**Per-VM 10G addresses:**

| VM | Hostname | Address | Gateway |
|---|---|---|---|
| VM 1 (control-plane) | `nico-cp-1` | `172.16.0.80/24` | `172.16.0.1` |
| VM 2 (worker) | `nico-worker-1` | `172.16.0.81/24` | `172.16.0.1` |
| VM 3 (worker) | `nico-worker-2` | `172.16.0.82/24` | `172.16.0.1` |

Repeat Step 4 on VM 2 and VM 3 with their respective IPs.

#### Step 5 — Verify IP and connectivity

```bash
# IP must be present
ip addr | grep "inet "
# inet 172.16.0.80/24   brd 172.16.0.255   scope global eth0  ✅

# Ping 10G gateway
ping -c2 172.16.0.1

# Ping nico-worker-1 — confirms cross-VM SSH will work
ping -c2 172.16.0.81
```

#### Step 7 — Set hostname, /etc/hosts, and fix DNS resolution order

```bash
# On VM1:  sudo hostnamectl set-hostname nico-cp-1
# On VM2:  sudo hostnamectl set-hostname nico-worker-1
# On VM3:  sudo hostnamectl set-hostname nico-worker-2

# Add to /etc/hosts on EVERY VM (required for kubeadm + Calico Felix)
sudo tee -a /etc/hosts <<'EOF'
127.0.0.1  localhost
::1        localhost ip6-localhost ip6-loopback
172.16.0.80  nico-cp-1
172.16.0.81  nico-worker-1
172.16.0.82  nico-worker-2
EOF

# Verify localhost resolves locally (must NOT go to external DNS):
getent hosts localhost
# 127.0.0.1  localhost  ✅

# Ensure /etc/nsswitch.conf resolves hosts via 'files' BEFORE 'dns'
# (prevents Calico Felix from timing out trying to resolve 'localhost' via 8.8.8.8)
grep "^hosts" /etc/nsswitch.conf
# Must be:  hosts:  files dns
# If 'dns' appears before 'files', fix it:
sudo sed -i 's/^hosts:.*/hosts:          files dns/' /etc/nsswitch.conf
grep "^hosts" /etc/nsswitch.conf
# hosts:          files dns  ✅
```

> **Why this matters for Calico:** Felix's health endpoint does `net.Listen("tcp",
> "localhost:9099")` which triggers an OS DNS lookup for `localhost`. In an
> air-gapped network with `8.8.8.8` as the nameserver, that lookup times out,
> causing Felix to repeatedly fail and restart. Ensuring `localhost → 127.0.0.1`
> is resolved from `/etc/hosts` (files first in nsswitch) eliminates this entirely.

### 0e. Enable SSH and Configure Key-Based Access (Optional)

Perform these steps **on each VM via the Prism console** while you still have
console access. After this you will reach VMs via the jump host.

#### Step 1 — Install and enable SSH server

```bash
sudo systemctl status ssh

# If not installed:
sudo apt-get update && sudo apt-get install -y openssh-server

sudo systemctl enable ssh
sudo systemctl start ssh

ss -tlnp | grep :22
# LISTEN  0  128  0.0.0.0:22   ← confirms sshd is up
```

#### Step 2 — Harden SSH configuration

```bash
sudo tee /etc/ssh/sshd_config.d/99-nico-hardening.conf <<'EOF'
PasswordAuthentication no
ChallengeResponseAuthentication no
AllowUsers ubuntu
PermitRootLogin no
ClientAliveInterval 60
ClientAliveCountMax 10
MaxAuthTries 3
EOF

sudo sshd -t   # test config — must print nothing (no errors)
```

> **Important:** Do **not** restart sshd yet — add your public key first (Step 3).

#### Step 3 — Generate SSH key pair on `nico-cp-1`

Run this **on `nico-cp-1`** (`172.16.0.80`):

```bash
ssh-keygen -t ed25519 -C "nico-lab-$(hostname)" -f ~/.ssh/id_nico_lab
cat ~/.ssh/id_nico_lab.pub
# ssh-ed25519 AAAA...  nico-lab-yourhost
```

#### Step 4 — Install the public key on each VM (via console)

```bash
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "ssh-ed25519 AAAA... nico-lab-yourhost" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Or push from `nico-cp-1` once workers have IPs (using password auth before
it is disabled):

```bash
# From nico-cp-1 via jump host:
ssh-copy-id -i ~/.ssh/id_nico_lab.pub root@172.16.0.81   # nico-worker-1
ssh-copy-id -i ~/.ssh/id_nico_lab.pub root@172.16.0.82   # nico-worker-2
```

#### Step 5 — Restart SSH and verify key login

```bash
sudo systemctl restart ssh
sudo systemctl is-active ssh   # must print: active
```

Test cross-VM SSH **from `nico-cp-1`**:

```bash
ssh -i ~/.ssh/id_nico_lab root@172.16.0.81   # nico-worker-1
ssh -i ~/.ssh/id_nico_lab root@172.16.0.82   # nico-worker-2

# Add shortcut aliases:
cat >> ~/.ssh/config <<'EOF'

Host nico-worker-1
    HostName 172.16.0.81
    User ubuntu
    IdentityFile ~/.ssh/id_nico_lab

Host nico-worker-2
    HostName 172.16.0.82
    User ubuntu
    IdentityFile ~/.ssh/id_nico_lab
EOF

chmod 600 ~/.ssh/config
```

Configure ProxyJump on **your laptop** for direct access to cluster VMs:

```bash
# ~/.ssh/config on your laptop:
cat >> ~/.ssh/config <<'EOF'

Host jump
    HostName 10.17.48.50
    User root

Host nico-cp-1
    HostName 172.16.0.80
    User ubuntu
    ProxyJump jump

Host nico-worker-1
    HostName 172.16.0.81
    User ubuntu
    ProxyJump jump

Host nico-worker-2
    HostName 172.16.0.82
    User ubuntu
    ProxyJump jump
EOF
```

#### Step 6 — Disable UFW (Ubuntu firewall)

```bash
sudo ufw disable
sudo systemctl disable ufw
sudo systemctl stop ufw
sudo ufw status
# Status: inactive  ✅
```

> Kubernetes components (kube-proxy, Calico, MetalLB) manage `iptables` rules
> directly. UFW will interfere with these rules.

| Port | Protocol | Purpose |
|---|---|---|
| 6443 | TCP | kube-apiserver |
| 2379–2380 | TCP | etcd (control-plane only) |
| 10250 | TCP | kubelet API |
| 10256 | TCP | kube-proxy health |
| 179 | TCP | Calico BGP |
| 4789 | UDP | Calico VXLAN |
| 67 | UDP | DHCP (MetalLB VIP) |
| 80, 443 | TCP | PXE / NICo API (MetalLB VIPs) |

#### Step 7 — Install sudo without password (optional, for DevSpace/scripts)

```bash
echo "ubuntu ALL=(ALL) NOPASSWD:ALL" \
  | sudo tee /etc/sudoers.d/ubuntu-nopasswd
sudo chmod 440 /etc/sudoers.d/ubuntu-nopasswd
```

---

After completing Phase 0e, **close the Prism console**. All remaining phases
run via SSH through the jump host:

```bash
# From your laptop:
ssh -J root@10.17.48.50 root@172.16.0.80    # direct to nico-cp-1

# Or if ~/.ssh/config is set up:
ssh nico-cp-1

# From nico-cp-1, reach workers:
ssh nico-worker-1   # 172.16.0.81
ssh nico-worker-2   # 172.16.0.82
```

---

## Air-Gap Note — Staging Files via Jump Host

> **The `172.16.0.x` network has no internet access.**
> All binaries, packages, manifests, and Helm charts must be **downloaded on
> the jump host** (`10.17.48.50`) and copied to `nico-cp-1` before running
> the phases below.
>
> **Jump host staging directory:** `/root/Documents/Manoj_temp/`
>
> From your laptop you can also copy files directly to `nico-cp-1` via ProxyJump:
> ```bash
> scp -J root@10.17.48.50 <file> root@172.16.0.80:~/
> ```

### Pre-Stage All Required Files (run once on jump host)

SSH into the jump host and run the following to download everything into the
staging directory. Then copy to `nico-cp-1` in bulk.

```bash
# On jump host (10.17.48.50):
ssh root@10.17.48.50

STAGE=/root/Documents/Manoj_temp
mkdir -p $STAGE
cd $STAGE

# --- DPU boot artifacts (required for forge.bfb build — see Phase 9 DPU Build) ---
# node-exporter ARM64 binary (embedded in forge-dpu.deb)
wget https://github.com/prometheus/node_exporter/releases/download/v1.8.2/node_exporter-1.8.2.linux-arm64.tar.gz

# transceiver-exporter ARM64 binary (embedded in forge-dpu.deb)
wget https://github.com/wobcom/transceiver-exporter/releases/download/v1.5.0/transceiver-exporter-v1.5.0-linux-arm64.tar.gz

# Go toolchain (used by build-otelcol to compile custom otelcol-contrib for DPU)
wget https://golang.org/dl/go1.22.0.linux-amd64.tar.gz

# Calico CNI manifest ---
curl -LO https://raw.githubusercontent.com/projectcalico/calico/v3.28.1/manifests/calico.yaml

# --- Docker GPG key ---
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o docker.gpg

# --- Kubernetes APT GPG key ---
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key -o kubernetes-release.key

# --- helm installer script ---
curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 -o get-helm-3.sh
chmod +x get-helm-3.sh

# --- helmfile binary ---
curl -sSL https://github.com/helmfile/helmfile/releases/download/v0.171.0/helmfile_0.171.0_linux_amd64.tar.gz \
  -o helmfile_0.171.0_linux_amd64.tar.gz

# --- devspace binary ---
curl -sSL https://github.com/loft-sh/devspace/releases/latest/download/devspace-linux-amd64 \
  -o devspace

# --- kubectl binary ---
curl -LO https://dl.k8s.io/release/v1.30.4/bin/linux/amd64/kubectl

# --- MetalLB helm chart (must use helm pull — GitHub release tarball is NOT a helm chart) ---
# Requires helm installed on jump host. Install if missing:
#   curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
helm repo add metallb https://metallb.github.io/metallb
helm repo update
helm pull metallb/metallb --version 0.14.5 --destination $STAGE
# Produces: $STAGE/metallb-0.14.5.tgz  (a valid helm chart tarball)

# --- helm-diff plugin tarball ---
curl -sSL https://github.com/databus23/helm-diff/releases/download/v3.9.9/helm-diff-linux-amd64.tgz \
  -o helm-diff-linux-amd64.tgz

# --- DevSpace build base image (for Phase 7b — Rust compiler) ---
docker pull rust:1.90.0-slim-bookworm
docker save rust:1.90.0-slim-bookworm | gzip > $STAGE/rust-1.90.0-slim-bookworm.tar.gz

# --- carbide-runtime-base (for Phase 7b — pre-baked runtime with kea/grpc/ssh) ---
# apt-get inside docker builds needs HTTP (port 80) to Debian mirrors.
# Route it through the squid proxy (172.16.0.50:3128) which handles HTTP via CONNECT.
# Build directly on nico-cp-1 (see Phase 7b Step 1 for full details).
# Nothing to stage here — built on nico-cp-1 using the proxy.

# --- cert-manager helm chart (for Phase 6 bootstrap — must use helm pull) ---
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm pull jetstack/cert-manager --version v1.15.3 --destination $STAGE
# Produces: $STAGE/cert-manager-v1.15.3.tgz

# --- cert-manager container images (all on quay.io — unreachable from 172.16.0.x) ---
docker pull quay.io/jetstack/cert-manager-controller:v1.15.3
docker pull quay.io/jetstack/cert-manager-cainjector:v1.15.3
docker pull quay.io/jetstack/cert-manager-webhook:v1.15.3
docker pull quay.io/jetstack/cert-manager-startupapicheck:v1.15.3
docker save quay.io/jetstack/cert-manager-controller:v1.15.3 \
  | gzip > $STAGE/cert-manager-controller-v1.15.3.tar.gz
docker save quay.io/jetstack/cert-manager-cainjector:v1.15.3 \
  | gzip > $STAGE/cert-manager-cainjector-v1.15.3.tar.gz
docker save quay.io/jetstack/cert-manager-webhook:v1.15.3 \
  | gzip > $STAGE/cert-manager-webhook-v1.15.3.tar.gz
docker save quay.io/jetstack/cert-manager-startupapicheck:v1.15.3 \
  | gzip > $STAGE/cert-manager-startupapicheck-v1.15.3.tar.gz

# --- Container images needed by bootstrap-prereqs.sh (Phase 6) ---
# These are pulled from Docker Hub — unreachable from 172.16.0.x
docker pull postgres:14.5-alpine
docker pull hashicorp/vault:1.20.2
docker save postgres:14.5-alpine | gzip > $STAGE/postgres-14.5-alpine.tar.gz
docker save hashicorp/vault:1.20.2 | gzip > $STAGE/vault-1.20.2.tar.gz

# --- Clone NICo repo (for Phase 5) ---
git clone https://github.com/nurametal/ncx-infra-controller-core.git

# --- Build carbide-admin-cli (for Phase 9 — requires Rust toolchain) ---
# Install Rust if not present: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cd ncx-infra-controller-core
cargo build --release -p carbide-admin-cli
cp target/release/carbide-admin-cli $STAGE/
cd $STAGE

# Verify all files are present:
ls -lh $STAGE
# Expected:
#   calico.yaml
#   docker.gpg
#   kubernetes-release.key
#   get-helm-3.sh
#   helmfile_0.171.0_linux_amd64.tar.gz
#   devspace
#   kubectl
#   metallb-0.14.5.tgz                       (helm chart — via 'helm pull')
#   helm-diff-linux-amd64.tgz
#   cert-manager-v1.15.3.tgz                 (helm chart — via 'helm pull')
#   cert-manager-controller-v1.15.3.tar.gz   (quay.io image)
#   cert-manager-cainjector-v1.15.3.tar.gz   (quay.io image)
#   cert-manager-webhook-v1.15.3.tar.gz      (quay.io image)
#   cert-manager-startupapicheck-v1.15.3.tar.gz  (quay.io image)
#   postgres-14.5-alpine.tar.gz              (Docker Hub image)
#   vault-1.20.2.tar.gz                      (Docker Hub image)
#   rust-1.90.0-slim-bookworm.tar.gz         (Docker Hub — devspace Rust build base)
#   carbide-runtime-base.tar.gz             (built on nico-cp-1 via squid proxy — see Phase 7b Step 1)
#   carbide-admin-cli
#   ncx-infra-controller-core/  (directory)
#   node_exporter-1.8.2.linux-arm64.tar.gz  (DPU build — ARM64 node-exporter)
#   transceiver-exporter-v1.5.0-linux-arm64.tar.gz  (DPU build — ARM64 transceiver-exporter)
#   go1.22.0.linux-amd64.tar.gz             (DPU build — Go toolchain for otelcol-contrib)
```

Now copy everything to `nico-cp-1` in one shot:

```bash
# On jump host — copy entire staging dir to nico-cp-1:
scp -r /root/Documents/Manoj_temp root@172.16.0.80:~/staged

# Also copy the repo to the home directory directly:
scp -r /root/Documents/Manoj_temp/ncx-infra-controller-core root@172.16.0.80:~/

# Verify on nico-cp-1:
ssh root@172.16.0.80 'ls -lh ~/staged/ && ls ~/ncx-infra-controller-core/'
```

> Push the staged packages to worker nodes too (needed for Phases 1e/1f):
> ```bash
> # On nico-cp-1 — forward staging dir to workers:
> scp -r ~/staged root@172.16.0.81:~/   # nico-worker-1
> scp -r ~/staged root@172.16.0.82:~/   # nico-worker-2
> ```

---

## Phase 1 — Prepare Ubuntu VMs (run on ALL VMs)

### 1a. Verify network, SSH, and firewall

Static IPs, SSH keys, and firewall settings were all configured in **Phase 0d/0e**.
Confirm everything is ready before running kubeadm.

```bash
# 1. IP must be present
ip addr | grep "inet "
# inet 172.16.0.80/24   ← eth0 / 10G (management + kubeadm API server)

# 2. Routes must exist
ip route
# default via 172.16.0.1 dev eth0
# 172.16.0.0/24  dev eth0

# 3. SSH daemon is running and key auth works
sudo systemctl is-active ssh          # active
sudo grep -i passwordauthentication /etc/ssh/sshd_config.d/99-nico-hardening.conf
# PasswordAuthentication no

# 4. Firewall is disabled
sudo ufw status
# Status: inactive  ✅
```

Cross-VM connectivity check (run from `nico-cp-1`):

```bash
ping -c2 172.16.0.81    # nico-worker-1 via 10G
ping -c2 172.16.0.82    # nico-worker-2 via 10G

# SSH check (must work key-only, no password prompt):
ssh nico-worker-1 hostname   # → should print: nico-worker-1
```

### 1c. OS baseline

```bash
sudo apt-get update && sudo apt-get upgrade -y

# Disable swap permanently (required for kubelet)
sudo swapoff -a
sudo sed -i '/\bswap\b/d' /etc/fstab

# Verify swap is off
free -h
# Swap: 0B
```

### 1d. Required kernel parameters

```bash
cat <<'EOF' | sudo tee /etc/sysctl.d/99-kubernetes.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sudo modprobe br_netfilter
echo br_netfilter | sudo tee /etc/modules-load.d/br_netfilter.conf
sudo sysctl --system

# Verify — both must be 1
sysctl net.ipv4.ip_forward net.bridge.bridge-nf-call-iptables
```

### 1e. Install containerd

> **Air-gap:** The Docker GPG key and APT repo require internet. Use the staged
> file from `~/staged/docker.gpg` (downloaded to jump host in the pre-stage step).

```bash
# Run on ALL VMs (nico-cp-1, nico-worker-1, nico-worker-2)

sudo apt-get install -y ca-certificates curl gnupg lsb-release

# --- Install Docker GPG key from staged file (no internet needed) ---
sudo install -m 0755 -d /etc/apt/keyrings
sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg ~/staged/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# --- Add Docker APT repo (points to internet but packages are fetched next) ---
echo "deb [arch=$(dpkg --print-architecture) \
  signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list

# --- If apt-get update fails (no internet) — download .deb on jump host first ---
# On jump host:
#   apt-get download containerd.io   (or use apt-get install --download-only)
#   scp containerd.io_*.deb root@172.16.0.80:~/staged/
# Then on each VM:
#   sudo dpkg -i ~/staged/containerd.io_*.deb

# If internet IS reachable via the repo (jump host acts as proxy), run normally:
sudo apt-get update
sudo apt-get install -y containerd.io

# Enable SystemdCgroup (required for kubeadm)
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' \
  /etc/containerd/config.toml

sudo systemctl restart containerd
sudo systemctl enable containerd

# Verify
sudo systemctl is-active containerd
```

### 1f. Install kubeadm, kubelet, kubectl

> **Air-gap:** Kubernetes APT repo GPG key is staged at `~/staged/kubernetes-release.key`.

```bash
# Run on ALL VMs

sudo apt-get install -y apt-transport-https ca-certificates curl gpg

# --- Install Kubernetes GPG key from staged file (no internet needed) ---
sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg \
  ~/staged/kubernetes-release.key

echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' \
  | sudo tee /etc/apt/sources.list.d/kubernetes.list

# --- If apt-get update/install fails (no internet) — download .debs on jump host ---
# On jump host:
#   curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key \
#     | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
#   echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] \
#     https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' \
#     | tee /etc/apt/sources.list.d/kubernetes.list
#   apt-get update
#   apt-get install --download-only -y kubelet=1.30.4-1.1 kubeadm=1.30.4-1.1 kubectl=1.30.4-1.1
#   cp /var/cache/apt/archives/kube*.deb /root/Documents/Manoj_temp/
#   scp /root/Documents/Manoj_temp/kube*.deb root@172.16.0.80:~/staged/
# Then on each VM:
#   sudo dpkg -i ~/staged/kube*.deb

# If APT repo IS reachable, run normally:
sudo apt-get update
sudo apt-get install -y kubelet=1.30.4-1.1 kubeadm=1.30.4-1.1 kubectl=1.30.4-1.1
sudo apt-mark hold kubelet kubeadm kubectl
sudo systemctl enable kubelet

# Verify
kubeadm version && kubectl version --client
```

---

## Phase 2 — Bootstrap Kubernetes Cluster

### 2a. Initialize control-plane (`nico-cp-1` — `172.16.0.80`)

```bash
sudo kubeadm init \
  --kubernetes-version=v1.30.4 \
  --pod-network-cidr=10.244.0.0/16 \
  --apiserver-advertise-address=172.16.0.80 \
  --control-plane-endpoint=172.16.0.80

# SAVE the kubeadm join command printed at the end — needed in step 2c
```

> `--apiserver-advertise-address` must be the VM's **10G IP** (`eth0`, `172.16.0.80`).
> This is where `kubectl` and `devspace` connect — reachable from the jump host.

Set up kubectl for your user:

```bash
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
export KUBECONFIG=$HOME/.kube/config
echo 'export KUBECONFIG=$HOME/.kube/config' >> ~/.bashrc
```

### 2b. Install Calico CNI

> **Air-gap:** `calico.yaml` was downloaded to `~/staged/calico.yaml` in the
> pre-stage step. Do not use the `https://` URL — it requires internet.

```bash
# On nico-cp-1 — apply from local staged file:
kubectl apply -f ~/staged/calico.yaml

# Wait for control-plane node to become Ready (~60–90s)
kubectl get nodes -w
# Ctrl-C when STATUS=Ready
```

> If `~/staged/calico.yaml` is missing, copy it from the jump host:
> ```bash
> scp root@10.17.48.50:/root/Documents/Manoj_temp/calico.yaml ~/staged/
> ```

### 2c. Join worker VMs (Ubuntu VM 2 and VM 3)

On **each worker VM**:

```bash
# Use the join command from step 2a output.
# If token expired (>24h), regenerate on VM1:
#   kubeadm token create --print-join-command

sudo kubeadm join 172.16.0.80:6443 \
  --token <token> \
  --discovery-token-ca-cert-hash sha256:<hash>
```

Example:
```bash
kubeadm join 172.16.0.80:6443 --token 7vk1mv.pc1u6xte9qwx6x2u \
	--discovery-token-ca-cert-hash sha256:e722bcf561f0a25fcb5dc4ee3af41b3445e2cd972eb66ea69fd9b4321dee0f3c
```

Label worker nodes:
```bash
kubectl label node nico-worker-1 node-role.kubernetes.io/worker=worker
kubectl label node nico-worker-2 node-role.kubernetes.io/worker=worker
```

### 2d. Verify cluster + Fix Calico BIRD Not Ready

```bash
kubectl get nodes -o wide
# NAME            STATUS   ROLES           VERSION   INTERNAL-IP
# nico-cp-1       Ready    control-plane   v1.30.4   172.16.0.80
# nico-worker-1   Ready    worker          v1.30.4   172.16.0.81
# nico-worker-2   Ready    worker          v1.30.4   172.16.0.82

kubectl get pods -n kube-system
# All Running: coredns, calico, etcd, kube-apiserver, kube-scheduler, kube-proxy
```

#### Calico BIRD Not Ready — Fix

> **See also:** [`DEBUG.md — Calico BIRD Not Ready`](DEBUG.md#calico-bird-not-ready)

If `calico-node` pods are stuck in `Running 0/1` with errors like:

```
Readiness probe failed: BIRD is not ready: unable to connect to BIRDv4 socket
Liveness probe failed: command "/bin/calico-node -felix-live -bird-live" timed out
```

**Root cause:** Calico's IP autodetection may pick the wrong interface
for BGP peering, causing BIRD (Calico's BGP daemon) to fail to bind.

**Fix — pin Calico IP autodetection to `eth0`:**

```bash
# Patch the calico-node DaemonSet to explicitly use eth0 (172.16.0.x) for BGP:
kubectl set env daemonset/calico-node -n kube-system \
  IP_AUTODETECTION_METHOD=interface=eth0 \
  IP6_AUTODETECTION_METHOD=none

# Wait for calico-node pods to roll out (~60s):
kubectl rollout status daemonset/calico-node -n kube-system

# Verify all calico-node pods are 1/1 Running:
kubectl get pods -n kube-system -l k8s-app=calico-node
# NAME                  READY   STATUS    RESTARTS
# calico-node-xxxx      1/1     Running   0         ✅
# calico-node-yyyy      1/1     Running   0         ✅
```

> **Why `interface=eth0`?** Calico BIRD needs to bind BGP to a single, routable
> interface. `eth0` carries the `172.16.0.x` addresses used by kubeadm — it is
> the correct interface for intra-cluster pod routing.

**If pods still fail after the patch**, check that the IP autodetection actually
resolved to the correct address:

```bash
# Confirm calico-node picked up 172.16.0.x as its node IP:
kubectl get node nico-cp-1 -o jsonpath='{.metadata.annotations.projectcalico\.org/IPv4Address}'
# Should print: 172.16.0.80/24  ✅

# Also check felix logs for any lingering errors:
kubectl logs -n kube-system -l k8s-app=calico-node --tail=30 | grep -i "bird\|felix\|error"
```

**Permanent fix — patch `calico.yaml` before applying (preferred for re-deploys):**

Rather than patching after the fact every time, edit `~/staged/calico.yaml` to
add the env vars directly so they are applied on first install:

```bash
# Add IP_AUTODETECTION_METHOD to calico.yaml before kubectl apply:
# Find the section with name: IP_AUTODETECTION_METHOD (it exists but may be empty)
# and set its value, or add it if missing.

# Quickest way with sed — run on nico-cp-1 before Phase 2b apply:
sed -i 's|# Auto-detect the BGP IP address.|# Auto-detect the BGP IP address.|' \
  ~/staged/calico.yaml

# More reliable — use kubectl patch after apply as shown above,
# OR edit the DaemonSet env block in calico.yaml directly:
#   Find:  name: IP_AUTODETECTION_METHOD
#           value: ""
#   Replace with:
#           value: "interface=eth0"
```

> For repeated re-deploys, permanently edit `~/staged/calico.yaml` to set:
> ```yaml
> - name: IP_AUTODETECTION_METHOD
>   value: "interface=eth0"
> - name: IP6_AUTODETECTION_METHOD
>   value: "none"
> ```
> This avoids needing the `kubectl set env` patch on every fresh cluster.

#### Calico Felix Health Endpoint Failure — Fix

> **See also:** [`DEBUG.md — Calico Felix DNS Timeout`](DEBUG.md#calico-felix-health-endpoint--dns-timeout)

If after the BIRD fix you see Felix errors like:

```
Health endpoint failed, trying to restart it...
error=listen tcp: lookup localhost on 8.8.8.8:53: read udp 172.16.0.80:xxxxx->8.8.8.8:53: i/o timeout
```

**Root cause (confirmed):** The NICo VM hostnames (`nico-cp-1`, `nico-worker-1`,
`nico-worker-2`) and `localhost` entries were **missing from `/etc/hosts`** on one
or more nodes. Felix and kubeadm both rely on hostname resolution from `/etc/hosts`
in an air-gapped environment where external DNS (`8.8.8.8`) is unreachable. When
the entry is absent the OS falls through to the DNS resolver, which times out.

**Fix — add all required entries to `/etc/hosts` on every node:**

```bash
# Run on ALL nodes (nico-cp-1, nico-worker-1, nico-worker-2):

# 1. Ensure localhost entries are present:
grep -q "^127.0.0.1.*localhost" /etc/hosts || \
  echo "127.0.0.1  localhost" | sudo tee -a /etc/hosts
grep -q "^::1.*localhost" /etc/hosts || \
  echo "::1        localhost ip6-localhost ip6-loopback" | sudo tee -a /etc/hosts

# 2. Ensure all NICo VM names are resolvable:
grep -q "nico-cp-1" /etc/hosts || sudo tee -a /etc/hosts <<'EOF'
172.16.0.80  nico-cp-1
172.16.0.81  nico-worker-1
172.16.0.82  nico-worker-2
EOF

# Verify all resolve immediately without hitting the network:
getent hosts localhost       # 127.0.0.1  localhost  ✅
getent hosts nico-cp-1      # 172.16.0.80  nico-cp-1  ✅
getent hosts nico-worker-1  # 172.16.0.81  nico-worker-1  ✅
```

**Restart calico-node after the fix:**

```bash
kubectl rollout restart daemonset/calico-node -n kube-system
kubectl rollout status daemonset/calico-node -n kube-system

kubectl get pods -n kube-system -l k8s-app=calico-node
# All 1/1 Running  ✅
```

> **Prevention:** Phase 0d Step 7 now includes all required `/etc/hosts` entries.
> Always complete Step 7 on every VM **before** running `kubeadm init` to avoid
> this error entirely on fresh deploys.

### 2e. Access kubeconfig from your laptop (optional)

```bash
# From your laptop via jump host:
ssh -J root@10.17.48.50 root@172.16.0.80 'cat ~/.kube/config' > ~/.kube/nico-lab.config
export KUBECONFIG=~/.kube/nico-lab.config
kubectl get nodes
```

---

## Phase 3 — Install Tools (on `nico-cp-1` — `172.16.0.80`)

> **Air-gap:** All binaries were pre-staged to `~/staged/` in the jump-host
> pre-stage step. Commands below install from `~/staged/` — no internet needed.

```bash
# --- helm (install from staged script) ---
bash ~/staged/get-helm-3.sh
helm version

# --- helmfile (install from staged tarball) ---
tar -xzf ~/staged/helmfile_0.171.0_linux_amd64.tar.gz -C /tmp/
sudo mv /tmp/helmfile /usr/local/bin/
helmfile --version

# --- helm-diff plugin (install from staged tarball, offline) ---
mkdir -p ~/.local/share/helm/plugins/helm-diff
tar -xzf ~/staged/helm-diff-linux-amd64.tgz -C ~/.local/share/helm/plugins/helm-diff
# Verify:
helm plugin list | grep diff

# --- devspace (install from staged binary) ---
sudo install -m 0755 ~/staged/devspace /usr/local/bin/devspace
devspace version

# --- kubectl (install from staged binary) ---
sudo install -m 0755 ~/staged/kubectl /usr/local/bin/kubectl
kubectl version --client

# --- jq (APT — may work if OS base repo is reachable; else download .deb) ---
# If internet-reachable:
sudo apt-get install -y jq
# If air-gapped (download on jump host first):
#   apt-get download jq && scp jq_*.deb root@172.16.0.80:~/staged/
#   sudo dpkg -i ~/staged/jq_*.deb

# --- Docker (for DevSpace image builds) ---
# 1. Remove Ubuntu's stock containerd
sudo apt-get remove -y containerd

# 2. Install Docker GPG key from staged file
sudo install -m 0755 -d /etc/apt/keyrings
sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg ~/staged/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list

# --- Install Docker packages ---
# If APT repo is reachable (via jump host proxy or IT routing):
sudo apt-get update
sudo apt-get install -y containerd.io docker-ce docker-ce-cli \
  docker-buildx-plugin docker-compose-plugin

# If fully air-gapped — download .debs on jump host first:
#   cd /root/Documents/Manoj_temp
#   apt-get install --download-only containerd.io docker-ce docker-ce-cli \
#     docker-buildx-plugin docker-compose-plugin
#   scp *.deb root@172.16.0.80:~/staged/
# Then on nico-cp-1:
#   sudo dpkg -i ~/staged/containerd.io_*.deb
#   sudo dpkg -i ~/staged/docker-ce_*.deb ~/staged/docker-ce-cli_*.deb \
#     ~/staged/docker-buildx-plugin_*.deb ~/staged/docker-compose-plugin_*.deb

# 3. Fix containerd config for Kubernetes (SystemdCgroup = true)
sudo containerd config default | sudo tee /etc/containerd/config.toml
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl restart containerd

# 4. Add user to docker group for DevSpace
sudo usermod -aG docker $USER
newgrp docker

# 5. Verify K8s still healthy
kubectl get nodes
sudo systemctl status containerd kubelet

# Final verification:
helm version && devspace version && kubectl version --client
```

---

## Phase 4 — Install MetalLB

> **Air-gap:** The MetalLB Helm chart tarball was pulled via `helm pull` on the
> jump host and staged to `~/staged/metallb-0.14.5.tgz`.
>
> **Important:** The `.tgz` must come from `helm pull`, **not** `curl` from
> GitHub's release page — the GitHub download is a source archive
> (`application/octet-stream`), not a valid Helm chart, and will produce:
> `Error: file does not appear to be a gzipped archive`.

```bash
# Verify the staged file is a valid helm chart before installing:
file ~/staged/metallb-0.14.5.tgz
# Must show: gzip compressed data  ✅
# If it shows 'application/octet-stream' or 'ASCII text' — it is the wrong file;
# re-pull it on the jump host using 'helm pull' (see pre-stage step).

# Install from staged helm chart tarball (no internet required):
helm install metallb ~/staged/metallb-0.14.5.tgz \
  --namespace metallb-system --create-namespace \
  --wait

kubectl get pods -n metallb-system
# controller and speaker pods should be Running
```

> If the `.tgz` is missing from `~/staged/`, re-pull it on the jump host:
> ```bash
> # On jump host:
> helm repo add metallb https://metallb.github.io/metallb
> helm repo update
> helm pull metallb/metallb --version 0.14.5 --destination /root/Documents/Manoj_temp/
> scp /root/Documents/Manoj_temp/metallb-0.14.5.tgz ubuntu@172.16.0.80:~/staged/
> ```

Apply VIP pools and L2 advertisements — one per network (on `nico-cp-1`):

```bash

# direnv and arping (APT — base OS repo usually reachable; else .deb via jump host)
sudo apt-get install -y direnv arping

cat <<'EOF' | kubectl apply -f -
# --- VLAN 101: BMC OOB (10G Switch) — also VM management ---
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: nico-vips-vlan101
  namespace: metallb-system
spec:
  addresses:
    - 172.16.0.85-172.16.0.95     # reserved range, above DHCP ceiling .60
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: l2-advert-vlan101
  namespace: metallb-system
spec:
  ipAddressPools:
    - nico-vips-vlan101
  interfaces:
    - eth0     # 10G NIC — renamed via udev (was ens5/ens4), carries 172.16.0.x
EOF

kubectl get ipaddresspool -n metallb-system
kubectl get l2advertisement -n metallb-system
```

> The `172.16.0.85–.95` range is assigned to NICo's LoadBalancer services via MetalLB.
> These are the VIPs that switches/BMCs use to reach NICo:
>
> | VIP | Service | Consumer |
> |---|---|---|
> | `172.16.0.85` | `carbide-dhcp` (UDP 67) | 10G Switch `ip helper-address` |
> | `172.16.0.86` | `carbide-pxe` (TCP 80) | BMC PXE boot `next-server` · serves `forge.bfb` for Redfish SimpleUpdate |
> | `172.16.0.87/88` | `carbide-dns` (UDP/TCP 53) | Tenant/VPC dynamic records via NICo API — **NOT** the `.forge` zone |
> | `172.16.0.89` | `carbide-api` (TCP 443) | Scout agent · admin CLI |
> | `172.16.0.90` | `carbide-ssh-console` (TCP 22) | SSH serial console to BMCs (when enabled) |
> | `172.16.0.91` | `forge-unbound` (UDP/TCP 53) | `.forge` zone resolver — advertised by carbide-dhcp as `carbide-nameservers`; resolves `carbide-pxe.forge`, `carbide-api.forge`, `carbide-static-pxe.forge`, `carbide-ntp.forge`, `unbound.forge` |

Verify MetalLB can ARP on VLAN 101:

```bash
# No response until carbide-dhcp and carbide-pxe pods are Running
sudo arping -I eth0 -c3 172.16.0.85
# Expected: reply from <speaker pod MAC>
```

---

## Phase 5 — Clone Repo and Configure NICo

> **Air-gap:** GitHub is not reachable from `172.16.0.x`. Clone the repo on the
> jump host and copy it to `nico-cp-1`, or clone on your laptop and `scp` via
> ProxyJump.

**Option A — Clone on jump host, copy to `nico-cp-1`:**

```bash
# On jump host (10.17.48.50):
cd /root/Documents/Manoj_temp
git clone https://github.com/nurametal/ncx-infra-controller-core.git

# Copy to nico-cp-1:
scp -r ncx-infra-controller-core root@172.16.0.80:~/
```

**Option B — Clone on your laptop, copy via ProxyJump:**

```bash
# On your laptop:
git clone https://github.com/nurametal/ncx-infra-controller-core.git
scp -J root@10.17.48.50 -r ncx-infra-controller-core root@172.16.0.80:~/
```

```bash
# On nico-cp-1 (after copy):
cd ~/ncx-infra-controller-core
direnv allow

# Verify ipxe submodule is initialized
ls ~/nurametal/infra-controller-core/pxe/ipxe/upstream/src/
# Should show iPXE source files (Makefile, core/, arch/, etc.)
# If empty, run:
cd ~/nurametal/infra-controller-core
git submodule update --init --recursive
```

### 5a. `helm-prereqs/values.yaml`

```yaml
siteName: "nurametal-lab"

postgresql:
  instances: 3
  volumeSize: "10Gi"
  resources:
    limits:
      cpu: "4"
      memory: "4Gi"
    requests:
      cpu: "500m"
      memory: "1Gi"
```

### 5b. `helm-prereqs/values/metallb-config.yaml`

```yaml
# VLAN 101 — BMC OOB (10G Switch)
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: nico-vips-vlan101
  namespace: metallb-system
spec:
  addresses:
    - 172.16.0.85-172.16.0.95
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: l2-advert-vlan101
  namespace: metallb-system
spec:
  ipAddressPools:
    - nico-vips-vlan101
  interfaces:
    - eth0     # 10G NIC — renamed via udev (was ens5/ens4)
```

### 5c. `helm-prereqs/values/ncx-core.yaml`

```yaml
carbide-api:
  hostname: "carbide-api.lab.nurametal"

  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "172.16.0.89"

  siteConfig:
    enabled: true
    carbideApiSiteConfig: |
      sitename             = "nurametal-lab"
      initial_domain_name  = "lab.nurametal"
      attestation_enabled  = false
      max_database_connections = 64

      # carbide-dhcp VIP on the 10G network handles both Host BMC and DPU BMC.
      # The 10G Switch (VLAN 101) relays all BMC DHCP to 172.16.0.85.
      dhcp_servers = ["172.16.0.85"]

      [pools.lo-ip]
      type   = "ipv4"
      ranges = [{ start = "172.16.0.100", end = "172.16.0.200" }]

      [pools.vlan-id]
      type   = "integer"
      ranges = [{ start = "102", end = "501" }]

      [pools.vni]
      type   = "integer"
      ranges = [{ start = "1024500", end = "1024550" }]

      # VLAN 101 — BMC OOB management network (10G Switch)
      [networks.admin]
      type          = "admin"
      prefix        = "172.16.0.0/24"
      gateway       = "172.16.0.1"
      mtu           = 1500
      reserve_first = 2

      [site_explorer]
      enabled              = true
      create_machines      = true
      allow_zero_dpu_hosts = true
      explore_mode         = "nv-redfish"
      run_interval         = "30s"
      machines_created_per_run = 100

      [machine_state_controller]
      failure_retry_time = "90m"

      [machine_validation_config]
      enabled = false

carbide-dhcp:
  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "172.16.0.85"

carbide-pxe:
  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "172.16.0.86"

carbide-dns:
  externalService:
    enabled: true
  perPodAnnotations:
    - metallb.universe.tf/loadBalancerIPs: "172.16.0.87"
    - metallb.universe.tf/loadBalancerIPs: "172.16.0.88"

carbide-ssh-console-rs:
  externalService:
    enabled: true
    annotations:
      metallb.universe.tf/loadBalancerIPs: "172.16.0.90"

carbide-dsx-exchange-consumer:
  enabled: false

## unbound — `.forge` zone resolver consumed by BMCs on the OOB network.
## DPU and host BMCs resolve `carbide-pxe.forge` here during Redfish BFB
## install. carbide-dhcp (above) advertises 172.16.0.91 as the nameserver
## so DHCP'd BMCs pick this up automatically.
unbound:
  enabled: true
  image:
    repository: "forge/unbound"
    tag: "1.20.0-<repo-short-sha>"
    pullPolicy: IfNotPresent
  exporterImage:
    repository: "forge/unbound_exporter"
    tag: "0.4.6-<repo-short-sha>"
    pullPolicy: IfNotPresent
  externalService:
    enabled: true
    type: LoadBalancer
    annotations:
      metallb.universe.tf/loadBalancerIPs: "172.16.0.91"
  localConfig:
    forwarders.conf: |
      forward-zone:
        name: "."
        forward-addr: 8.8.8.8
        forward-addr: 1.1.1.1
    local_data.conf: |
      server:
        local-zone: "forge." static
        local-data: "carbide-api.forge.        300 IN A 172.16.0.89"
        local-data: "carbide-pxe.forge.        300 IN A 172.16.0.86"
        local-data: "carbide-static-pxe.forge. 300 IN A 172.16.0.86"
        local-data: "carbide-ntp.forge.        300 IN A 172.16.0.80"
        local-data: "unbound.forge.            300 IN A 172.16.0.91"
```

### 5d. `dev/deployment/devspace/values.base.yaml` — physical machine mode

```yaml
carbide-api:
  siteConfig:
    enabled: true
    carbideApiSiteConfig: |
      sitename             = "nurametal-lab"
      initial_domain_name  = "lab.nurametal"
      attestation_enabled  = false
      dpu_ipmi_tool_impl   = "ipmi"
      max_database_connections = 64
      # 10G Switch (VLAN 101) relays BMC DHCP to this VIP.
      dhcp_servers = ["172.16.0.85"]

      [pools.lo-ip]
      type   = "ipv4"
      ranges = [{ start = "172.16.0.100", end = "172.16.0.200" }]

      [pools.vlan-id]
      type   = "integer"
      ranges = [{ start = "102", end = "501" }]

      [pools.vni]
      type   = "integer"
      ranges = [{ start = "1024500", end = "1024550" }]

      # VLAN 101 — BMC OOB (10G Switch)
      [networks.admin]
      type          = "admin"
      prefix        = "172.16.0.0/24"
      gateway       = "172.16.0.1"
      mtu           = 1500
      reserve_first = 2

      [site_explorer]
      enabled              = true
      create_machines      = true
      allow_zero_dpu_hosts = true
      explore_mode         = "nv-redfish"
      run_interval         = "30s"

      [machine_state_controller]
      skip_polling_checks = false
      failure_retry_time  = "90m"

carbide-dhcp:
  enabled: true
carbide-pxe:
  enabled: true
carbide-dns:
  enabled: true
carbide-hardware-health:
  enabled: true
carbide-dsx-exchange-consumer:
  enabled: false
```

---

## Phase 6 — Bootstrap Prerequisites (one-time)

### Option A: DevSpace-only bootstrap (dev/test — lighter)

> **Air-gap:** `bootstrap-prereqs.sh` internally runs `helm repo add jetstack
> https://charts.jetstack.io` which fails in this network. It also deploys
> `postgres:14.5-alpine` and `hashicorp/vault:1.20.2` from Docker Hub.
> Follow the steps below to handle all of this offline.

#### Step 1 — Load container images into containerd on ALL nodes

cert-manager images come from `quay.io/jetstack`, Postgres from Docker Hub,
and Vault from Docker Hub — all unreachable from `172.16.0.x`. Run this on
`nico-cp-1`, `nico-worker-1`, and `nico-worker-2` so pods can be scheduled
on any node:

```bash
# On EACH node (nico-cp-1, nico-worker-1, nico-worker-2):

# cert-manager images (quay.io/jetstack):
sudo ctr -n k8s.io images import ~/staged/cert-manager-controller-v1.15.3.tar.gz
sudo ctr -n k8s.io images import ~/staged/cert-manager-cainjector-v1.15.3.tar.gz
sudo ctr -n k8s.io images import ~/staged/cert-manager-webhook-v1.15.3.tar.gz
sudo ctr -n k8s.io images import ~/staged/cert-manager-startupapicheck-v1.15.3.tar.gz

# Postgres + Vault images (Docker Hub):
sudo ctr -n k8s.io images import ~/staged/postgres-14.5-alpine.tar.gz
sudo ctr -n k8s.io images import ~/staged/vault-1.20.2.tar.gz

# Verify all six images are present:
sudo crictl images | grep -E "cert-manager|postgres|vault"
# quay.io/jetstack/cert-manager-controller        v1.15.3  ✅
# quay.io/jetstack/cert-manager-cainjector        v1.15.3  ✅
# quay.io/jetstack/cert-manager-webhook           v1.15.3  ✅
# quay.io/jetstack/cert-manager-startupapicheck   v1.15.3  ✅
# docker.io/library/postgres                      14.5-alpine  ✅
# docker.io/hashicorp/vault                       1.20.2   ✅
```

#### Step 2 — Install cert-manager from staged chart

The bootstrap script installs cert-manager via `helm repo add jetstack` —
skip that by installing cert-manager manually first, then telling the script
to skip its own cert-manager step via `LOCAL_DEV_INSTALL_CERT_MANAGER=0`:

```bash
# On nico-cp-1:
helm install cert-manager ~/staged/cert-manager-v1.15.3.tgz \
  --namespace cert-manager --create-namespace \
  --set crds.enabled=true

# Wait for all three cert-manager deployments to be ready:
kubectl rollout status deployment/cert-manager -n cert-manager --timeout=180s
kubectl rollout status deployment/cert-manager-cainjector -n cert-manager --timeout=180s
kubectl rollout status deployment/cert-manager-webhook -n cert-manager --timeout=180s

kubectl get pods -n cert-manager
# All Running ✅
```

#### Step 3 — Install StorageClass

```bash
cd ~/ncx-infra-controller-core

kubectl apply -f helm-prereqs/operators/local-path-provisioner.yaml
kubectl apply -f helm-prereqs/operators/storageclass-local-path-persistent.yaml
kubectl annotate storageclass local-path \
  storageclass.kubernetes.io/is-default-class=true --overwrite
```

#### Step 4 — Run bootstrap skipping cert-manager install

```bash
# LOCAL_DEV_INSTALL_CERT_MANAGER=0 skips the helm repo add / helm install
# inside the script (cert-manager is already installed from Step 2 above)
LOCAL_DEV_INSTALL_CERT_MANAGER=0 \
  dev/deployment/devspace/bootstrap-prereqs.sh
```

Expected output:
```
[local-dev] Configuring Vault mounts and local role
WARNING! The following warnings were returned from Vault:

  * This mount hasn't configured any authority information access (AIA)
  fields; this may make it harder for systems to find missing certificates
  in the chain or to validate revocation status of certificates. Consider
  updating /config/urls or the newly generated issuer with this information.

[local-dev] Applying local cert-manager issuer resources
clusterissuer.cert-manager.io/local-selfsigned created
certificate.cert-manager.io/forge-local-ca created
issuer.cert-manager.io/local-ca-issuer created
secret/forge-roots created

Bootstrap complete.

Namespace: forge-system
Generated values: /root/nurametal/infra-controller-core/dev/deployment/devspace/values.generated.yaml
Postgres endpoint: postgres.postgres.svc.cluster.local:5432/carbide
Vault address: http://vault.vault.svc.cluster.local:8200
Cert issuer: Issuer/local-ca-issuer

Next step:
  cd /root/nurametal/infra-controller-core && devspace deploy -n forge-system
```

#### Step 5 — Verify all prereq pods are running

```bash
kubectl get pods -n cert-manager
kubectl get pods -n vault
kubectl get pods -n postgres
# All Running ✅
```

### Option B: Full production bootstrap via `setup.sh` (TODO-Not Done)

```bash
export KUBECONFIG=~/.kube/config
export REGISTRY_PULL_SECRET=<ngc-api-key>
export NCX_IMAGE_REGISTRY=nvcr.io/nvstaging/ncx
export NCX_CORE_IMAGE_TAG=<tag>
export NCX_REST_IMAGE_TAG=<tag>

cd helm-prereqs/
./setup.sh -y    # installs Temporal, Keycloak, REST stack as well
```

---

## Phase 7 — Build and Deploy with DevSpace

### Key files for air-gapped local build

| File | Purpose |
|---|---|
| `dev/deployment/devspace/Dockerfile.runtime-base` | Pre-baked runtime base — `debian:bookworm-slim` + `kea-dhcp4-server` + all NICo runtime libs. Built once on `nico-cp-1` via `--build-arg SQUID_PROXY` so apt-get goes through the squid proxy (port 80 is blocked direct). Proxy vars are cleared after install. **Must be rebuilt whenever this file changes.** |
| `dev/deployment/devspace/Dockerfile.all-services` | Main build Dockerfile for the `carbide-api` image — compiles ALL service binaries (`carbide-api`, `carbide-pxe`, `carbide-dns`, `forge-dhcp-server`, `forge-hw-health`, `ssh-console`, `libdhcp.so`) in one image. Uses `FROM carbide-runtime-base` (no apt-get on `nico-cp-1`). Runs `cargo clean -p carbide-rpc` to force proto codegen every build. Passes `SQUID_PROXY` for Cargo crate downloads. |
| `dev/deployment/devspace/Dockerfile.bmc-proxy` | Builds `carbide-bmc-proxy` image — single Rust binary, Ubuntu 24.04 runtime. Passes `SQUID_PROXY` for both Cargo and apt stages. |
| `dev/deployment/devspace/Dockerfile.machine-a-tron` | Builds `machine-a-tron` image (BMC simulator) — single Rust binary, Debian bookworm-slim runtime. Passes `SQUID_PROXY` for both Cargo and apt stages. |
| `devspace.yaml` | Orchestrates all three image builds — passes `$SQUID_PROXY` shell env var as `--build-arg` to each `docker build`. |
| `dev/deployment/devspace/values.base.yaml` | Helm values — `carbide-dhcp`, `carbide-pxe`, `carbide-dns`, `carbide-hardware-health` all `enabled: true`. VNI/vpc-vni pool ranges set to 76k entries. |

### 7a. Set image registry (NGC / production only)

> **Air-gapped lab:** skip this step — images are built locally by DevSpace
> and imported directly into containerd (see Phase 7b).

```bash
# NGC registry (production / pre-built images only):
export NCX_IMAGE_REGISTRY=nvcr.io/nvstaging/ncx
export REGISTRY_PULL_SECRET=<ngc-api-key>
```

### 7b. Build images with DevSpace then import into containerd

> **How this works (air-gapped, no registry needed):**
> DevSpace builds images using the Docker daemon on `nico-cp-1`. Each built
> image is exported with `docker save` and imported directly into containerd's
> `k8s.io` namespace on **every node** with `ctr images import`. Kubernetes
> (kubelet) finds them locally with `imagePullPolicy: IfNotPresent` — no
> registry pull attempted.
>
> **Image coverage — one image serves all NICo services:**
> `Dockerfile.all-services` compiles every service binary in a single Docker
> build using `build-container-localdev`, then packages them all into one
> runtime image. All services (`carbide-dhcp`, `carbide-pxe`, `carbide-dns`,
> `carbide-hardware-health`) share this image and are enabled in
> `dev/deployment/devspace/values.base.yaml`.
>
> | Built image | Services |
> |---|---|
> | `carbide-api:<tag>` | carbide-api, carbide-dhcp, carbide-pxe, carbide-dns, carbide-hardware-health |
> | `carbide-bmc-proxy:<tag>` | carbide-bmc-proxy |
> | `machine-a-tron:<tag>` | machine-a-tron (BMC simulator) |

#### Step 1 — Pull the latest repo changes onto `nico-cp-1`

```bash
cd ~/ncx-infra-controller-core
git pull
```

#### Step 2 — Build `carbide-runtime-base` on `nico-cp-1`

`carbide-runtime-base` is a pre-baked Debian image with all NICo runtime
packages (`kea-dhcp4-server`, `libgrpc`, `libssh`, etc.). It must be built
using `apt-get`, which requires HTTP (port 80). The squid proxy handles this.

> **Rebuild whenever `Dockerfile.runtime-base` changes** — e.g. when packages
> are added or the kea version changes. Always use `--no-cache` to ensure a
> fresh package install.

> **Why apt-get needs the proxy:** `docker pull` uses HTTPS (port 443) which
> is open. But `apt-get` uses plain HTTP (port 80) to `deb.debian.org`, which
> is blocked at the network level. The squid proxy at `172.16.0.50:3128`
> tunnels HTTP via CONNECT. Proxy vars are cleared at the end of the Dockerfile
> so they don't leak into derived images or final image layers.

```bash
# On nico-cp-1:
cd ~/ncx-infra-controller-core

docker build \
  --build-arg SQUID_PROXY=http://172.16.0.50:3128 \
  --no-cache \
  -t carbide-runtime-base \
  -f dev/deployment/devspace/Dockerfile.runtime-base .

# Verify kea and key runtime libs are present:
docker run --rm carbide-runtime-base sh -c \
  "which kea-dhcp4 && ls /usr/lib/x86_64-linux-gnu/kea/hooks/"
# /usr/sbin/kea-dhcp4  ✅
```

#### Step 3 — Load Rust build base into Docker on `nico-cp-1`

```bash
# On nico-cp-1 — load the Rust compiler base (staged from jump host):
docker load -i ~/staged/rust-1.90.0-slim-bookworm.tar.gz

docker images | grep -E "rust|carbide-runtime"
# rust                    1.90.0-slim-bookworm   ...  ✅
# carbide-runtime-base    latest                 ...  ✅
```

#### Step 4 — Run `devspace deploy` (builds all images + deploys Helm chart)

DevSpace builds three images using the Docker daemon on `nico-cp-1`:

| Image | Dockerfile | Contents |
|---|---|---|
| `carbide-api:<tag>` | `Dockerfile.all-services` | carbide-api, carbide-pxe, carbide-dns, forge-dhcp-server, forge-hw-health, ssh-console, libdhcp.so |
| `carbide-bmc-proxy:<tag>` | `Dockerfile.bmc-proxy` | carbide-bmc-proxy binary |
| `machine-a-tron:<tag>` | `Dockerfile.machine-a-tron` | machine-a-tron binary |

All three Dockerfiles accept `--build-arg SQUID_PROXY` for Cargo crate downloads and apt installs. The `SQUID_PROXY` shell env var is picked up automatically by `devspace.yaml`.

```bash
# On nico-cp-1:
cd ~/ncx-infra-controller-core

# Wipe stale BuildKit cache first (important after a failed or partial build):
docker builder prune --filter type=exec.cachemount --force

export SQUID_PROXY=http://172.16.0.50:3128

# First-time build (Rust compile takes ~30–45 min):
devspace deploy -n forge-system

# Subsequent rebuilds after source changes:
devspace deploy -n forge-system --force-build
```

> **Troubleshooting — `file not found for module 'common'` / `forge` / `health`**
>
> Proto-generated `.rs` files are missing due to a stale BuildKit cache from a
> prior failed build. `Dockerfile.all-services` runs `cargo clean -p carbide-rpc`
> before each build to force regeneration, but a stale cache mount can override
> this. Fix:
>
> ```bash
> docker builder prune --filter type=exec.cachemount --force
> export SQUID_PROXY=http://172.16.0.50:3128
> devspace deploy -n forge-system --force-build
> ```

> **Troubleshooting — `Timeout was reached (download of 'axum-template' failed)`**
>
> Cargo cannot reach crates.io. Ensure `SQUID_PROXY` is exported before running
> `devspace deploy`. Verify proxy is reachable:
>
> ```bash
> curl -x http://172.16.0.50:3128 https://crates.io
> ```

> **Troubleshooting — `libdhcp.so: No such file or directory`**
>
> The `carbide-dhcp` cdylib failed to build. Two possible causes:
>
> **Cause 1 — Stale `build-container-localdev`** (missing kea-dev headers).
> Rebuild it — DevSpace recreates it automatically on next run:
>
> ```bash
> docker rmi build-container-localdev
> # Verify kea headers will be present after rebuild:
> # dev/docker/Dockerfile.build-container-x86_64 installs kea-dev
> export SQUID_PROXY=http://172.16.0.50:3128
> devspace deploy -n forge-system --force-build
> ```
>
> **Cause 2 — Stale BuildKit cache** from a prior partial build:
>
> ```bash
> docker builder prune --filter type=exec.cachemount --force
> export SQUID_PROXY=http://172.16.0.50:3128
> devspace deploy -n forge-system --force-build
> ```
>
> Verify kea headers exist inside the build container:
>
> ```bash
> docker run --rm build-container-localdev ls /usr/include/kea/
> ```

> **Troubleshooting — `/sbin/kea-dhcp4: not found` in pod logs**
>
> The `carbide-runtime-base` image used when building `carbide-api` was stale —
> it was built before `kea-dhcp4-server` was properly installed. Rebuild the
> runtime base (Step 2) then wipe the BuildKit cache and redeploy (Step 4).

#### Step 5 — Verify the new image contains all binaries

> **Run this after every `--force-build` before importing to nodes.**
> Pods will crash with "not found" if the image was built from a stale
> `carbide-runtime-base` that is missing kea packages.

```bash
TAG_API=$(docker images --format '{{.Tag}}' carbide-api | head -1)
echo "Verifying carbide-api:${TAG_API}"

docker run --rm carbide-api:${TAG_API} ls \
  /opt/carbide/carbide-api \
  /opt/carbide/carbide \
  /opt/carbide/carbide-dns \
  /opt/carbide/forge-dhcp-server \
  /opt/carbide/forge-hw-health \
  /opt/carbide/ssh-console \
  /sbin/kea-dhcp4 \
  /usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so
# All paths must print without errors ✅
# Any missing path = stale runtime-base or wrong Dockerfile used
# Fix: rebuild carbide-runtime-base (Step 2), wipe cache, redeploy (Step 4)
```

#### Step 6 — Import built images into containerd on ALL nodes

> **Each devspace image gets its own independent tag.** Do not assume all
> three share the same tag — look up each one separately.
>
> **Why `ctr -n k8s.io`?** Kubernetes uses the `k8s.io` containerd namespace.
> Images imported without `-n k8s.io` are invisible to kubelet.

```bash
# On nico-cp-1 — capture tags:
TAG_API=$(docker images --format '{{.Tag}}' carbide-api       | head -1)
TAG_BMC=$(docker images --format '{{.Tag}}' carbide-bmc-proxy | head -1)
TAG_MAT=$(docker images --format '{{.Tag}}' machine-a-tron    | head -1)
echo "carbide-api: $TAG_API  bmc-proxy: $TAG_BMC  machine-a-tron: $TAG_MAT"

# Import into containerd on nico-cp-1:
docker save carbide-api:${TAG_API}       | sudo ctr -n k8s.io images import -
docker save carbide-bmc-proxy:${TAG_BMC} | sudo ctr -n k8s.io images import -
docker save machine-a-tron:${TAG_MAT}    | sudo ctr -n k8s.io images import -

# Save tarballs and distribute to worker nodes:
docker save carbide-api:${TAG_API}       -o /tmp/carbide-api.tar
docker save carbide-bmc-proxy:${TAG_BMC} -o /tmp/carbide-bmc-proxy.tar
docker save machine-a-tron:${TAG_MAT}    -o /tmp/machine-a-tron.tar

for NODE in 172.16.0.81 172.16.0.82; do
  scp /tmp/carbide-api.tar /tmp/carbide-bmc-proxy.tar /tmp/machine-a-tron.tar \
      root@${NODE}:/tmp/
  ssh root@${NODE} "
    ctr -n k8s.io images import /tmp/carbide-api.tar
    ctr -n k8s.io images import /tmp/carbide-bmc-proxy.tar
    ctr -n k8s.io images import /tmp/machine-a-tron.tar
    ctr -n k8s.io images ls | grep -E 'carbide-api|carbide-bmc-proxy|machine-a-tron'
  "
done
```

#### Step 7 — Reset database and restart all pods

> Reset the postgres pod so resource pools (vpc-vni, vni, etc.) start fresh.
> This is needed when `carbide-api` crashes with "Resource pool missing or full"
> after re-deploying over an existing cluster.

```bash
# Wipe postgres so pools reset:
kubectl delete pod -n postgres --all
sleep 15

# Delete all forge-system jobs and pods — they restart automatically:
kubectl delete job -n forge-system --all
kubectl delete pod -n forge-system --all

# Watch until stable:
kubectl get pods -n forge-system -w
# Expected within ~60s:
#   carbide-api-migrate-*        Completed  ✅  (DB migration job)
#   carbide-api-*                Running    ✅
#   carbide-bmc-proxy-*          Running    ✅
#   carbide-dhcp-*               Running    ✅
#   carbide-dns-*                Running    ✅
#   carbide-hardware-health-*    Running    ✅
#   carbide-pxe-*                Running    ✅
#   machine-a-tron-*             Running    ✅
```

#### Step 8 — Verify services and MetalLB IPs

```bash
kubectl get pods -n forge-system
# Expected:
#   carbide-api-*              Running    ✅
#   carbide-bmc-proxy-*        Running    ✅
#   carbide-dhcp-*             Running    ✅
#   carbide-pxe-*              Running    ✅
#   carbide-dns-0              Running    ✅
#   carbide-hardware-health-*  Running    ✅
#   machine-a-tron-*           Running    ✅
#   carbide-api-migrate-*      Completed  ✅

kubectl get svc -n forge-system
# All LoadBalancer services should have MetalLB IPs assigned:
#   carbide-api-external          LoadBalancer   172.16.0.89
#   carbide-dhcp-external         LoadBalancer   172.16.0.85
#   carbide-pxe-external          LoadBalancer   172.16.0.86
#   carbide-dns-0-external        LoadBalancer   172.16.0.87
#   carbide-dns-1-external        LoadBalancer   172.16.0.88
#   forge-unbound-external        LoadBalancer   172.16.0.91   <-- .forge zone
```

## Example response of devspace deploy -n forge-system:
info Using namespace 'forge-system'
info Using kube context 'kubernetes-admin@kubernetes'
build:machine-a-tron Skip building image 'machine-a-tron'
build:carbide-api Skip building image 'carbide-api'
build:carbide-bmc-proxy Skip building image 'carbide-bmc-proxy'
Execute hook 'load-images-into-local-cluster' at before:deploy
deploy:carbide-local Deploying chart  (carbide-local) with helm...
deploy:machine-a-tron-local Applying manifests with kubectl...
deploy:machine-a-tron-local serviceaccount/machine-a-tron unchanged
deploy:machine-a-tron-local configmap/machine-a-tron-config unchanged
deploy:machine-a-tron-local certificate.cert-manager.io/machine-a-tron-certificate unchanged
deploy:machine-a-tron-local service/machine-a-tron-bmc-mock unchanged
deploy:machine-a-tron-local deployment.apps/machine-a-tron unchanged
deploy:machine-a-tron-local Successfully deployed machine-a-tron-local with kubectl
deploy:carbide-local Deployed helm chart (Release revision: 2)
deploy:carbide-local Successfully deployed carbide-local with helm
####
```

#### On subsequent `devspace deploy` runs

After the first successful build, `devspace` skips rebuilding unchanged images.
After each `--force-build`, re-run Steps 5–7 to import new images and restart
pods.

Convenience script — run after every `devspace deploy --force-build`:

```bash
# On nico-cp-1:
TAG_API=$(docker images --format '{{.Tag}}' carbide-api       | head -1)
TAG_BMC=$(docker images --format '{{.Tag}}' carbide-bmc-proxy | head -1)
TAG_MAT=$(docker images --format '{{.Tag}}' machine-a-tron    | head -1)

# Verify new carbide-api image has all binaries before distributing:
docker run --rm carbide-api:${TAG_API} ls \
  /opt/carbide/carbide-api /opt/carbide/carbide /opt/carbide/carbide-dns \
  /opt/carbide/forge-dhcp-server /sbin/kea-dhcp4 \
  /usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp.so

# Save tarballs (no gzip — ctr import handles plain tar fine and is faster):
docker save carbide-api:${TAG_API}       -o /tmp/carbide-api.tar
docker save carbide-bmc-proxy:${TAG_BMC} -o /tmp/carbide-bmc-proxy.tar
docker save machine-a-tron:${TAG_MAT}    -o /tmp/machine-a-tron.tar

# Import on nico-cp-1:
sudo ctr -n k8s.io images import /tmp/carbide-api.tar
sudo ctr -n k8s.io images import /tmp/carbide-bmc-proxy.tar
sudo ctr -n k8s.io images import /tmp/machine-a-tron.tar

# Copy and import on workers:
for NODE in 172.16.0.81 172.16.0.82; do
  scp /tmp/carbide-api.tar /tmp/carbide-bmc-proxy.tar /tmp/machine-a-tron.tar \
      root@${NODE}:/tmp/
  ssh root@${NODE} "
    ctr -n k8s.io images import /tmp/carbide-api.tar
    ctr -n k8s.io images import /tmp/carbide-bmc-proxy.tar
    ctr -n k8s.io images import /tmp/machine-a-tron.tar
  "
done

# Force helm to re-run pre-install hooks (migration job) and restart all pods:
devspace deploy -n forge-system --force-deploy
kubectl get pods -n forge-system -w
```

---

### 7c. Troubleshooting reference

> **Full troubleshooting details in [`DEBUG.md`](DEBUG.md)**

| Symptom | Cause | Fix |
|---|---|---|
| `relation "resource_pool_def" does not exist` | Migration job never ran — DB schema missing | Force redeploy: `devspace deploy -n forge-system --force-deploy` |
| `carbide-api-migrate` job `NotFound` | Helm pre-install hook skipped (devspace cached deploy) | `devspace deploy -n forge-system --force-deploy` |
| `ServiceAccount "carbide-api" cannot be imported … must equal "carbide"` | Wrong helm release name used in manual `helm` command | Use `helm upgrade --install carbide-local` or just `devspace deploy --force-deploy` |
| `/sbin/kea-dhcp4: not found` in pod | Stale `carbide-runtime-base` missing kea packages | Rebuild with `--no-cache` (Step 2), wipe BuildKit cache, redeploy |
| `UrlParseError("")` in machine-a-tron | `http_proxy` env baked into image — service only accepts `socks5://` | Rebuild image (fixed: proxy passed via shell `RUN` not `ENV`) |
| `libdhcp.so: No such file or directory` | `carbide-dhcp` cdylib build failed silently | `docker rmi build-container-localdev` then `--force-build` |
| `file not found for module 'common'/'forge'` | Stale BuildKit cargo cache, proto files not regenerated | `docker builder prune --filter type=exec.cachemount --force` then `--force-build` |
| Cargo `Timeout was reached (download of 'axum-template')` | Cargo not using proxy | `export SQUID_PROXY=http://172.16.0.50:3128` before `devspace deploy` |
| `ImagePullBackOff` on any pod | New image tag not imported into containerd on that node | `docker save <img>:<tag> \| sudo ctr -n k8s.io images import -` on all nodes |
| `Resource pool 'vpc-vni' missing or full` | DB exhausted from prior runs | `kubectl delete pod -n postgres --all && sleep 15 && kubectl delete pod -n forge-system --all` |
| All services are `ClusterIP`, no `LoadBalancer` / MetalLB IPs | `externalService.enabled: false` (chart default) — external services not created | Add `externalService.enabled: true` + MetalLB annotations to `values.base.yaml` then `devspace deploy --force-deploy` |
| `carbide-admin-cli`: `invalid peer certificate: certificate not valid for name "172.16.0.89"` | TLS cert is DNS-only — connecting via IP triggers SNI mismatch | Add `172.16.0.89 carbide-api.forge-system.svc.cluster.local` to `/etc/hosts`, use DNS name in `--carbide-api` |
| `carbide-admin-cli`: `EOF while parsing a value` panic | `~/.config/carbide_api_cli.json` is empty or malformed | Delete it and re-create with `tee`, or pass all flags explicitly |
| `carbide-admin-cli`: `UrlParseError("")` or `Only SOCKS5 Proxy supported` | `http_proxy`/`https_proxy` env vars set in shell | `unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY` before running CLI |

#### Migration job not created / `relation "resource_pool_def" does not exist`

> **See also:** [`DEBUG.md — Migration Job Not Created`](DEBUG.md#migration-job-not-created)

The `carbide-api-migrate` Job is a Helm `pre-install,pre-upgrade` hook.
It only runs when Helm executes an install or upgrade. If devspace's deploy
step is cached (no changes detected), Helm is skipped and the job never runs.
`carbide-api` then crashes because the DB tables don't exist.

```bash
# Check whether the job exists:
kubectl get job carbide-api-migrate -n forge-system

# If NotFound — force helm to re-run:
devspace deploy -n forge-system --force-deploy

# Watch migration complete before carbide-api starts:
kubectl get pods -n forge-system -w
# carbide-api-migrate-*   Running → Completed  ✅  (must finish first)
# carbide-api-*           Running              ✅
```

If the migration pod itself fails:

```bash
kubectl logs -n forge-system -l app=carbide-api-migrate --tail=50
```

Common migration failures:
- **`ImagePullBackOff`** — `carbide-api` image not in containerd for that node. Re-import and redeploy.
- **postgres connection refused** — postgres pod just restarted; wait for it:
  ```bash
  kubectl rollout status statefulset/postgres -n postgres --timeout=120s
  devspace deploy -n forge-system --force-deploy
  ```

#### Wrong helm release name

Manually running `helm upgrade --install carbide ...` (instead of `carbide-local`)
causes a conflict because devspace installed the release as `carbide-local`:

```
ServiceAccount "carbide-api" exists and cannot be imported into the current
release: annotation validation error: key "meta.helm.sh/release-name" must
equal "carbide": current value is "carbide-local"
```

Fix — use the correct release name:

```bash
TAG_API=$(docker images --format '{{.Tag}}' carbide-api       | head -1)
TAG_BMC=$(docker images --format '{{.Tag}}' carbide-bmc-proxy | head -1)

helm upgrade --install carbide-local ./helm \
  --namespace forge-system \
  --values dev/deployment/devspace/values.base.yaml \
  --values dev/deployment/devspace/values.generated.yaml \
  --set global.image.repository=carbide-api \
  --set global.image.tag=${TAG_API} \
  --set global.image.pullPolicy=IfNotPresent \
  --set carbide-bmc-proxy.image.repository=carbide-bmc-proxy \
  --set carbide-bmc-proxy.image.tag=${TAG_BMC} \
  --set carbide-bmc-proxy.image.pullPolicy=IfNotPresent
```

Or simply use devspace which handles the release name automatically:

```bash
devspace deploy -n forge-system --force-deploy
```

### 7d. Verify all services have VIPs

```bash
kubectl get svc -n forge-system | grep LoadBalancer
# carbide-api-external          LoadBalancer   172.16.0.89   443/TCP
# carbide-dhcp-external         LoadBalancer   172.16.0.85   67/UDP
# carbide-pxe-external          LoadBalancer   172.16.0.86   80/TCP
# carbide-dns-0-external        LoadBalancer   172.16.0.87   53/UDP,53/TCP
# carbide-dns-1-external        LoadBalancer   172.16.0.88   53/UDP,53/TCP
# forge-unbound-external        LoadBalancer   172.16.0.91   53/UDP,53/TCP   <-- .forge zone

kubectl get pods -n forge-system
# All Running — no CrashLoopBackOff
```

---

## Phase 7e — Using `carbide-admin-cli` from `nico-cp-1`

### Extract TLS credentials from the cluster

```bash
# All three files come from the machine-a-tron-certificate secret:
kubectl get secret machine-a-tron-certificate -n forge-system \
  -o jsonpath='{.data.ca\.crt}'  | base64 -d > /tmp/forge-ca.crt
kubectl get secret machine-a-tron-certificate -n forge-system \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/client.crt
kubectl get secret machine-a-tron-certificate -n forge-system \
  -o jsonpath='{.data.tls\.key}' | base64 -d > /tmp/client.key

# Verify all three are valid PEM:
head -1 /tmp/forge-ca.crt /tmp/client.crt /tmp/client.key
# -----BEGIN CERTIFICATE-----
# -----BEGIN CERTIFICATE-----
# -----BEGIN EC PRIVATE KEY-----
```

### Add DNS entry for `carbide-api`

The `carbide-api` TLS cert is issued for its DNS name, not its IP. Since
`nico-cp-1` is a VM host (not a pod), cluster DNS (`.svc.cluster.local`) does
not resolve on the host. Add it to `/etc/hosts`:

```bash
echo "172.16.0.89 carbide-api.forge-system.svc.cluster.local" >> /etc/hosts
getent hosts carbide-api.forge-system.svc.cluster.local
# 172.16.0.89  carbide-api.forge-system.svc.cluster.local  ✅
```

### Save CLI config (run once)

```bash
mkdir -p ~/.config
tee ~/.config/carbide_api_cli.json << 'JSONEOF'
{
  "carbide_api": "https://carbide-api.forge-system.svc.cluster.local:443",
  "forge_root_ca_path": "/tmp/forge-ca.crt",
  "client_cert_path": "/tmp/client.crt",
  "client_key_path": "/tmp/client.key"
}
JSONEOF

# Verify valid JSON:
python3 -m json.tool ~/.config/carbide_api_cli.json
```

> **Note:** `/tmp` files are lost on reboot — re-extract certs after each reboot,
> or copy them to a persistent path (e.g. `~/.config/forge-ca.crt`) and update
> the JSON accordingly.

> **Note:** Unset proxy vars before running the CLI — the CLI only accepts
> `socks5://` proxies and will crash with `UrlParseError` on `http://` or
> empty values:
> ```bash
> unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
> ```

### Verify CLI works

```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
./carbide-admin-cli machine show

or 

env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
  ./carbide-admin-cli \
    --carbide-api https://carbide-api.forge-system.svc.cluster.local:443 \
    --forge-root-ca-path /tmp/forge-ca.crt \
    --client-cert-path  /tmp/client.crt \
    --client-key-path   /tmp/client.key \
    machine show


or 

export CARBIDE_API="https://carbide-api.forge-system.svc.cluster.local:443"
alias ncli="./carbide-admin-cli --carbide-api $CARBIDE_API --forge-root-ca-path /tmp/forge-ca.crt  --client-cert-path  /tmp/client.crt  --client-key-path  /tmp/client.key"

# Returns list of machines (empty if none registered yet) ✅
```

### Common `carbide-admin-cli` examples

All examples below assume the config file `~/.config/carbide_api_cli.json` is
populated (see above) and proxy vars are unset.  The binary path `./carbide-admin-cli`
should be replaced with the full path if it is not in your `$PATH`.

#### Health / version check

```bash
# Print the server-side version of carbide-api
./carbide-admin-cli version
```

#### Machine operations

```bash
# List all registered machines
./carbide-admin-cli machine show

# Show a specific machine by ID
./carbide-admin-cli machine show --machine-id <MACHINE-UUID>

# Show hardware info (CPU, memory, NIC details) for a machine
./carbide-admin-cli machine hardware-info --machine-id <MACHINE-UUID>

# Show health report for a machine
./carbide-admin-cli machine health-report --machine-id <MACHINE-UUID>

# Reboot a machine via BMC
./carbide-admin-cli machine reboot --machine-id <MACHINE-UUID>
```

#### BMC operations

```bash
# List BMC credentials known to NICo
./carbide-admin-cli credential show

# Power cycle a machine through its BMC
./carbide-admin-cli bmc-machine admin-power-control \
    --machine-id <MACHINE-UUID> \
    --action power-cycle

# Reset the BMC itself (useful after firmware update)
./carbide-admin-cli bmc-machine bmc-reset \
    --machine-id <MACHINE-UUID>
```

#### Network segments

```bash
# List configured network segments (shows BMC/DPU VLANs)
./carbide-admin-cli network-segment show
```

#### OS images and iPXE templates

```bash
# List OS images registered with NICo
./carbide-admin-cli operating-system show

# List iPXE boot templates
./carbide-admin-cli ipxe-template show
```

#### Instance lifecycle

```bash
# List all compute instances
./carbide-admin-cli instance show

# Release an instance (returns the machine to the free pool)
./carbide-admin-cli instance release --instance-id <INSTANCE-UUID>
```

#### Resource pools

```bash
# Show VNI / VPC resource pool state (useful to diagnose "pool full" errors)
./carbide-admin-cli resource-pool show
```

#### Inventory

```bash
# Show full hardware inventory discovered by NICo
./carbide-admin-cli inventory show
```

#### One-liner to run with explicit flags (no config file)

If you haven't created the JSON config file yet you can pass everything inline:

```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY

./carbide-admin-cli \
  --carbide-api https://carbide-api.forge-system.svc.cluster.local:443 \
  --forge-root-ca-path /tmp/forge-ca.crt \
  --client-cert-path  /tmp/client.crt \
  --client-key-path   /tmp/client.key \
  machine show
```

> **Tip:** Pipe output through `python3 -m json.tool` or `jq .` for
> human-readable JSON formatting, e.g.:
> ```bash
> ./carbide-admin-cli machine show | python3 -m json.tool
> ```

---

## Phase 8 — Configure OOB Switch DHCP Relay

Configure on the **10G Switch** (VLAN 101 L3 interface) only.
NICo serves DHCP for both Host BMC and DPU BMC on the **10G BMC OOB network (VLAN 101)** only.

```
# Cumulus Linux
auto vlan101
iface vlan101
  address 172.16.0.1/24
  vlan-id 101
  dhcp-relay 172.16.0.85

# Arista EOS
interface Vlan101
  ip address 172.16.0.1/24
  ip helper-address 172.16.0.85

# Cisco IOS / NX-OS
interface Vlan101
  ip address 172.16.0.1 255.255.255.0
  ip helper-address 172.16.0.85

# SONiC
# config interface ip add Vlan101 172.16.0.1/24
# (DHCP relay via dhcp_relay container config)
```

Verify relay is working:

```bash
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-dhcp -f
# Expect: DHCPDISCOVER → DHCPOFFER → DHCPREQUEST → DHCPACK
```

---

## Apply `reserve_first` Change to a Running System

If NICo is already deployed and the `admin` network segment was created with the wrong
`reserve_first` value (e.g. `2` instead of `20`), carbide-api will allocate IPs starting
from `.2` instead of `.20`, potentially conflicting with static infrastructure addresses.

`reserve_first` is written to `network_prefixes.num_reserved` in PostgreSQL **only once**
(when the segment is first created). Changing `values.base.yaml` alone is not enough —
you must delete the segment from the DB and restart `carbide-api` to recreate it.

> **Warning:** This deletes all machine interface records associated with the admin
> segment. Only do this if no real machines have been provisioned yet, or after noting
> down any data you need to preserve.

```bash
# 1. Get the current admin segment ID
ncli network-segment show
# Note the UUID of the "admin" row

ADMIN_ID="<paste-admin-segment-uuid-here>"
PG_POD=$(kubectl get pods -n postgres \
  -o custom-columns=:metadata.name --no-headers | head -n1)

# 2. Delete all child records (FK order: addresses → dhcp_entries → interfaces)
kubectl exec -n postgres $PG_POD -- \
  psql -U postgres carbide -c "
    BEGIN;
    DELETE FROM machine_interface_addresses
      WHERE interface_id IN (
        SELECT id FROM machine_interfaces WHERE segment_id = '$ADMIN_ID'
      );
    DELETE FROM dhcp_entries
      WHERE machine_interface_id IN (
        SELECT id FROM machine_interfaces WHERE segment_id = '$ADMIN_ID'
      );
    DELETE FROM machine_interfaces WHERE segment_id = '$ADMIN_ID';
    COMMIT;
  "

# 3. Delete the prefix and segment itself
kubectl exec -n postgres $PG_POD -- \
  psql -U postgres carbide -c "
    BEGIN;
    DELETE FROM network_prefixes WHERE segment_id = '$ADMIN_ID';
    DELETE FROM network_segments WHERE id = '$ADMIN_ID';
    COMMIT;
  "

# 4. Redeploy with the updated values.base.yaml (reserve_first = 20)
devspace deploy --skip-build

# 5. Restart carbide-api — create_initial_networks will now recreate the segment
kubectl rollout restart deployment/carbide-api -n forge-system
kubectl rollout status deployment/carbide-api -n forge-system --timeout=120s

# 6. Verify reserve_first = 20 is in effect
ncli network-segment show
# admin row should show prefix 172.16.0.0/24
# First DHCP allocations will now start at 172.16.0.20
```

---

---

## Phase 9 — Register and Boot Physical Machines

### 9a. Build admin CLI (TODO - Run the build inside build-container-localdev (recommended for consistency)

Pre-req:
1) apt install cargo 
2)  apt install rustup
3) apt-get install -y protobuf-compiler
# Verify:
protoc --version

> **Air-gap:** `cargo build` downloads crates from `crates.io` on first build.
> Run the first build on the jump host (or your laptop) where internet is available,
> then copy the compiled binary to `nico-cp-1`.
>
> **Option A — Build on jump host, copy binary:**
> ```bash
> # On jump host (requires Rust toolchain installed):
> cd /root/Documents/Manoj_temp/ncx-infra-controller-core
> cargo build --release -p carbide-admin-cli
> scp target/release/carbide-admin-cli root@172.16.0.80:~/
> ```
>
> **Option B — Build locally with internet, copy binary via ProxyJump:**
> ```bash
> # On your laptop:
> cargo build --release -p carbide-admin-cli
> scp -J root@10.17.48.50 target/release/carbide-admin-cli root@172.16.0.80:~/
> ```

```bash
# On nico-cp-1 — use the pre-built binary (no cargo needed):
export CARBIDE_API="https://172.16.0.89:443"
alias ncli="$HOME/carbide-admin-cli -c $CARBIDE_API"

# Or if building directly on nico-cp-1 (requires Rust + internet for crates):
cd ncx-infra-controller-core
cargo build --release -p carbide-admin-cli
export CARBIDE_API="https://172.16.0.89:443"
alias ncli="env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY ./carbide-admin-cli --carbide-api $CARBIDE_API --forge-root-ca-path /tmp/forge-ca.crt  --client-cert-path  /tmp/client.crt  --client-key-path  /tmp/client.key"
```

### 9b. Set site-wide credentials (IPMI communication through carbide)

```bash
ncli credential add-bmc --kind=site-wide-root --password='nutanix/4u'
ncli host generate-host-uefi-password
  ( Example --> Generated Bios Admin Password: DaFQKLvH9zX8od2Z))
ncli credential add-uefi --kind=host --password='<uefi-password>'
```

### 9c. Register expected machines

```bash
cat > expected_machines.json <<'EOF'
{
  "expected_machines": [
    {
      "bmc_mac_address": "AA:BB:CC:DD:EE:01",
      "bmc_username": "root",
      "bmc_password": "<factory-default-password>",
      "chassis_serial_number": "SN-SUT-001"
    },
    {
      "bmc_mac_address": "AA:BB:CC:DD:EE:02",
      "bmc_username": "root",
      "bmc_password": "<factory-default-password>",
      "chassis_serial_number": "SN-SUT-002"
    }
  ]
}
EOF

ncli em replace-all --filename expected_machines.json
ncli em list   # verify
```

### 9d. Approve TPM trust (wildcard for lab)

```bash
ncli mb site trusted-machine approve \* persist --pcr-registers="0,3,5,6"
```

### 9e. Power on physical machines

```
BMC powers on
  → DHCP Discover on VLAN 101
  → 10G Switch relays to 172.16.0.85 (carbide-dhcp)
  → carbide-dhcp → gRPC → carbide-api → IP allocated from 172.16.0.20–.60
  → DHCP Offer: IP + next-server=172.16.0.86 (carbide-pxe)
  → Host PXE boots → downloads iPXE → boots Scout OS
  → Scout agent → mTLS/gRPC → carbide-api:443 → reports hardware inventory
  → DPU BMC gets DHCP on VLAN 101 → DPU Agent installed via Redfish
  → State machine: Discovering → Inventoried → Validated → Ready
```

---

## Phase 10 — Verify and Monitor

```bash
# Full cluster health
kubectl get nodes
kubectl get pods -n forge-system
kubectl get pods -n metallb-system
kubectl get pods -n cert-manager
kubectl get pods -n vault
kubectl get pods -n postgres
kubectl get svc -n forge-system | grep LoadBalancer

# Watch machine discovery state changes
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-api -f \
  | grep -i "state\|machine\|discover\|scout"

# Watch DHCP
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-dhcp -f

# Watch PXE
kubectl logs -n forge-system \
  -l app.kubernetes.io/name=carbide-pxe -f

# List machines and states
ncli machine list

# Admin web UI
# https://172.16.0.89/admin
```

---

## Cluster Delete and Full Cleanup

Use these steps to tear down state and re-deploy. There are **three tiers** —
pick the lightest one that matches your symptom. Going deeper than needed
costs ~30+ min of Rust rebuild time and avoidable risk.

| Tier | Scope | When to use | Time |
|------|-------|-------------|------|
| **Tier 1 — NICo state only** | `devspace purge` + DB wipe + `devspace deploy` | Stuck machine state, want fresh DPU ingest, DB schema/state corruption | ~5–10 min |
| **Tier 2 — NICo + prereqs**  | Tier 1 + cert-manager + Vault + Postgres + MetalLB | PKI/cert corruption, Vault unsealed, prereqs unhealthy | ~15–25 min |
| **Tier 3 — Full kubeadm**    | Tier 2 + full Kubernetes teardown on every node    | Kubernetes itself is corrupted (etcd loss, CNI broken on multiple nodes) | ~45–90 min |

> **Decision rule of thumb:** if `kubectl get pods -A` looks healthy except
> for forge-system, you almost certainly only need **Tier 1**. Confirm Postgres
> and Vault are healthy before reaching for Tier 2.

---

### Tier 1 — NICo state wipe (recommended for re-ingest)

Wipes all NICo Helm releases and the carbide database, then redeploys NICo on
top of healthy Kubernetes + prereqs. Use this when you want a clean slate for
DPU/host discovery without touching the rest of the stack.

```bash
ssh -J root@10.17.48.50 root@172.16.0.80   # nico-cp-1
cd ncx-infra-controller-core

# 1. Tear down all NICo Helm releases
devspace purge -n forge-system

# 2. Verify forge-system is empty
kubectl get all -n forge-system

# 3. Wipe the carbide DB (drops + recreates the database)
dev/deployment/devspace/nuke-postgres.sh

# 4. Confirm DB recreated and Postgres healthy
kubectl get pods -n postgres
kubectl exec -ti postgres-0 -n postgres -- psql -U postgres -c "\l" | grep carbide

# 5. Redeploy NICo (images cached → ~5 min, no Rust rebuild)
export SQUID_PROXY=http://172.16.0.50:3128
devspace deploy -n forge-system

# 6. Wait for all forge-system pods Ready
kubectl wait --for=condition=Ready pod \
  --all -n forge-system --timeout=300s

# 7. Confirm MetalLB VIPs reassigned
kubectl get svc -n forge-system | grep LoadBalancer
# Expected:
#   carbide-api-external     172.16.0.89   443/TCP
#   carbide-dhcp-external    172.16.0.85    67/UDP
#   carbide-pxe-external     172.16.0.86    80/TCP
#   forge-unbound-external   172.16.0.90    53/UDP,53/TCP
```

After Tier 1 completes, **skip to [Re-ingest Machines After Purge](#re-ingest-machines-after-purge)**.

---

### Tier 2 — NICo + prereqs teardown

Includes everything in Tier 1 plus cert-manager, Vault, Postgres operator,
external-secrets, and MetalLB. Required when PKI/certificates or Vault state
are suspected to be corrupted.

```bash
ssh -J root@10.17.48.50 root@172.16.0.80
cd ncx-infra-controller-core

# 1. Tear down NICo Helm releases first
devspace purge -n forge-system

# 2. Run the prereq cleanup script
cd helm-prereqs/
./clean.sh
# Destroys (in reverse dependency order):
#   - carbide-rest, temporal, keycloak
#   - carbide-prereqs, external-secrets, vault, cert-manager,
#     postgres-operator, MetalLB (helmfile releases)
#   - cluster-scoped resources (ClusterIssuers, ClusterSecretStores,
#     ClusterExternalSecrets, ClusterRoles)
#   - Vault init secrets
#   - Namespaces: forge-system, cert-manager, vault, external-secrets,
#     postgres, metallb-system
#   - Released PVs owned by this stack
#   - local-path-provisioner + StorageClass

# 3. Verify the relevant namespaces are gone
kubectl get ns
# forge-system, cert-manager, vault, external-secrets, postgres,
# metallb-system should be absent

# 4. Re-bootstrap prereqs
cd ..
./helm-prereqs/setup.sh

# 5. Redeploy NICo
export SQUID_PROXY=http://172.16.0.50:3128
devspace deploy -n forge-system
```

After Tier 2 completes, continue to [Re-ingest Machines After Purge](#re-ingest-machines-after-purge).

---

### Tier 3 — Full kubeadm teardown

Tears down Kubernetes itself on every node. Only use when k8s/etcd is
unrecoverable. Steps 1–9 below come from earlier lab debugging where the
control-plane became unreachable.

### Step 1 — Connect to the cluster via jump host

```bash
ssh -J root@10.17.48.50 root@172.16.0.80   # nico-cp-1
```

### Step 2 — Remove NICo services (keep Kubernetes + prereqs)

```bash
cd ncx-infra-controller-core

# Tear down all NICo Helm releases deployed via devspace
devspace purge -n forge-system

# Verify forge-system is empty
kubectl get all -n forge-system
```

### Step 3 — Nuke Postgres (wipe all machine/state data — fresh discovery)

```bash
dev/deployment/devspace/nuke-postgres.sh

# Verify Postgres pods recover
kubectl get pods -n postgres
```

### Step 4 — Remove NICo prereqs (cert-manager, Vault, Postgres)

```bash
cd ncx-infra-controller-core/helm-prereqs/
./clean.sh

# Verify namespaces are gone
kubectl get ns
# cert-manager, vault, postgres should no longer be present
```

### Step 5 — Remove MetalLB

```bash
helm uninstall metallb -n metallb-system
kubectl delete namespace metallb-system

# Also remove the CRD objects if they linger:
kubectl delete ipaddresspool --all -A 2>/dev/null || true
kubectl delete l2advertisement --all -A 2>/dev/null || true
```

### Step 6 — Remove locally imported containerd images (if needed)

```bash
# On each node — list and remove NICo images from containerd:
sudo ctr -n k8s.io images ls | grep -E "carbide-api|carbide-bmc-proxy|machine-a-tron" \
  | awk '{print $1}' | xargs -r sudo ctr -n k8s.io images rm
```

### Step 7 — Tear down kubeadm cluster

Run on **each worker node first**, then the control-plane:

```bash
# On nico-worker-1 (172.16.0.81):
ssh -J root@10.17.48.50 root@172.16.0.81
sudo kubeadm reset -f
sudo rm -rf /etc/kubernetes /var/lib/etcd ~/.kube
sudo systemctl stop kubelet
sudo iptables -F && sudo iptables -t nat -F && sudo iptables -t mangle -F
sudo ipvsadm --clear 2>/dev/null || true
exit

# On nico-worker-2 (172.16.0.82):
ssh -J root@10.17.48.50 root@172.16.0.82
sudo kubeadm reset -f
sudo rm -rf /etc/kubernetes /var/lib/etcd ~/.kube
sudo systemctl stop kubelet
sudo iptables -F && sudo iptables -t nat -F && sudo iptables -t mangle -F
exit

# On nico-cp-1 (172.16.0.80) — control-plane last:
ssh -J root@10.17.48.50 root@172.16.0.80
sudo kubeadm reset -f
sudo rm -rf /etc/kubernetes /var/lib/etcd ~/.kube
sudo systemctl stop kubelet
sudo iptables -F && sudo iptables -t nat -F && sudo iptables -t mangle -F
sudo ipvsadm --clear 2>/dev/null || true
exit
```

### Step 8 — Clean up CNI and network state (on all VMs)

```bash
# Run on each VM
sudo rm -rf /etc/cni/net.d /var/lib/cni /var/lib/calico
sudo ip link delete cni0 2>/dev/null || true
sudo ip link delete flannel.1 2>/dev/null || true
sudo ip link delete vxlan.calico 2>/dev/null || true
```

### Step 9 — Verify clean state

```bash
# On each VM — confirm no leftover kubernetes or calico processes
ps aux | grep -E "kube|etcd|calico" | grep -v grep
# Should return nothing

# Confirm no stale CNI interfaces
ip link show | grep -E "cni|calico|flannel|vxlan"
# Should return nothing
```

### Re-deploy after cleanup

```bash
# Re-initialize from Phase 2 (all VM packages remain installed):
ssh -J root@10.17.48.50 root@172.16.0.80

# On nico-cp-1:
sudo kubeadm init \
  --kubernetes-version=v1.30.4 \
  --pod-network-cidr=10.244.0.0/16 \
  --apiserver-advertise-address=172.16.0.80 \
  --control-plane-endpoint=172.16.0.80

mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

kubectl apply -f \
  https://raw.githubusercontent.com/projectcalico/calico/v3.28.1/manifests/calico.yaml

# Then continue from Phase 2c (join workers) → Phase 4 (MetalLB) → Phase 6 (bootstrap)
```

---

## Re-ingest Machines After Purge

After **any** tier of cleanup + redeploy, follow these steps to re-register
expected machines and trigger DPU/host discovery from scratch. This assumes
all NICo pods are Ready and the four LoadBalancer VIPs are assigned.

### Step A — Wire up the admin CLI

```bash
# Use the pre-built binary on nico-cp-1
export CARBIDE_API="https://172.16.0.89:443"
alias ncli="$HOME/carbide-admin-cli -c $CARBIDE_API"

# Or, if the binary uses explicit cert paths:
alias ncli="env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
  $HOME/carbide-admin-cli \
  --carbide-api $CARBIDE_API \
  --forge-root-ca-path /tmp/forge-ca.crt \
  --client-cert-path  /tmp/client.crt \
  --client-key-path   /tmp/client.key"

# Sanity check — should return an empty list
ncli machine list
```

If you get a TLS error, see [`DEBUG.md § CLI TLS Certificate Mismatch`](DEBUG.md#cli-tls-certificate-mismatch).

### Step B — Set site-wide credentials

These are the credentials carbide-api uses for outbound Redfish/IPMI calls to
BMCs. Must be set before any discovery cycle runs.

```bash
# Site-wide BMC root password (use the actual factory/site password)
ncli credential add-bmc --kind=site-wide-root --password='nutanix/4u'

# UEFI password — generates one, then save the printed value
ncli host generate-host-uefi-password
# Example:  Generated Bios Admin Password: DaFQKLvH9zX8od2Z

ncli credential add-uefi --kind=host --password='<generated-uefi-password>'
```

### Step C — Register expected machines

Carbide will not allocate a DHCP lease to any MAC that isn't in
`expected_machines.json`. Both **host BMC MAC** and **DPU BMC MAC** must be
registered — on BlueField-3 the DPU BMC MAC is one above the DPU ARM OS MAC
(e.g. `…:B0` is the ARM OS, `…:B1` is the BMC).

```bash
cat > expected_machines.json <<'EOF'
{
  "expected_machines": [
    {
      "bmc_mac_address": "<HOST-BMC-MAC>",
      "bmc_username": "ADMIN",
      "bmc_password": "<HOST-BMC-PASSWORD>",
      "chassis_serial_number": "<HOST-CHASSIS-SN>"
    },
    {
      "bmc_mac_address": "<DPU-BMC-MAC>",
      "bmc_username": "root",
      "bmc_password": "<DPU-BMC-PASSWORD>",
      "chassis_serial_number": "<DPU-CHASSIS-SN>"
    }
  ]
}
EOF

ncli em replace-all --filename expected_machines.json
ncli em show
```

> **NX nodes vs. Supermicro + BF-3 reference HW:** on NX, the DPU BMC is
> exposed as a sub-manager via the host BMC's Redfish (`/redfish/v1/Managers/Bluefield_BMC`).
> On Supermicro + BF-3, the DPU BMC is a separate device with its own
> dedicated 1GbE RJ45 OOB port on the BlueField card's bracket and its own
> DHCP lease. Verify by querying `GET /redfish/v1/Managers` on the host BMC —
> if you only see Manager `1` with no Bluefield sub-manager, you're on the
> Supermicro topology and DPU BMC connectivity is fully independent of the
> host BMC.

### Step D — Approve TPM trust (lab wildcard)

```bash
ncli mb site trusted-machine approve \* persist --pcr-registers="0,3,5,6"
```

For production, replace `\*` with the actual TPM SVID per host.

### Step E — Power-cycle the chassis to trigger fresh DHCP

A cold BMC reset clears stale UpdateService state from any previous failed
BFB install attempt; the subsequent power-on triggers a fresh DHCP DISCOVER
on VLAN 101 from all BMC NICs.

```bash
HOST_BMC=172.16.0.20            # adjust to your host BMC IP
BMC_USER=ADMIN                  # adjust if not Supermicro
BMC_PASS='nutanix/4u'

ipmitool -I lanplus -H "$HOST_BMC" -U "$BMC_USER" -P "$BMC_PASS" chassis power off
sleep 15
ipmitool -I lanplus -H "$HOST_BMC" -U "$BMC_USER" -P "$BMC_PASS" mc reset cold
sleep 120
ipmitool -I lanplus -H "$HOST_BMC" -U "$BMC_USER" -P "$BMC_PASS" chassis power on
```

### Step F — Watch ingestion in three parallel terminals

```bash
# Terminal 1 — DHCP traffic, filtered by your BMC MAC OUI
kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-dhcp -f \
  | grep -iE "84:eb:0c|7c:c2:55|DISCOVER|ALLOC|ADVERT"

# Terminal 2 — carbide-api state machine
kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-api -f \
  | grep -iE "explore|discover|state|dpu|bfb|scout|InstallingBFB"

# Terminal 3 — machine list as it populates
watch -n 10 'ncli machine list'
```

Expected progression:
```
DHCPDISCOVER → DHCPOFFER → DHCPACK    (DHCP for both BMC MACs)
  → carbide-api explores BMC via Redfish
  → machine row appears in ncli machine list
  → DpuDiscovering → DpuInit/InstallingBFB → ...
```

### Step G — Verify DPU BMC actually DHCP'd (BF-3 reference HW only)

On Supermicro + BF-3 the DPU BMC has its own dedicated 1GbE OOB port. If that
port is unplugged, in the wrong VLAN, or the BMC is wedged, you will see the
DPU ARM OS MAC (e.g. `…:B0`) get a lease but the DPU BMC MAC (`…:B1`) will
never appear. Check explicitly:

```bash
kubectl exec -n postgres -it postgres-0 -- psql -U carbide carbide -c "
  SELECT mac_address, address, last_invalidation_time
  FROM machine_dhcp_records
  WHERE mac_address ILIKE '<DPU-BMC-OUI>:%'
  ORDER BY mac_address;"
```

If the DPU BMC MAC is absent after the power cycle:

1. Confirm a cable is plugged into the **dedicated 1GbE RJ45 OOB port on the
   BlueField card's bracket** (not a QSFP port) and the link LED is lit.
2. Confirm that switch port is on VLAN 101 with `ip helper-address 172.16.0.85`.
3. From any host on `172.16.0.0/24`, sniff for the DPU BMC MAC directly:
   ```bash
   sudo tcpdump -i <oob-iface> -ne 'ether host <DPU-BMC-MAC>' -c 20
   ```
   No packets = physical / VLAN issue, not a Carbide problem.
4. If you suspect the DPU BMC firmware is wedged, recover via the host's
   rshim PCIe interface (on the host OS):
   ```bash
   sudo modprobe mst && sudo mst start
   sudo cat /dev/rshim0/misc        # shows DPU BMC network state
   sudo cat /dev/rshim0/console &   # tail the DPU BMC console
   ```

### Step H — Verify BFB ↔ BMC firmware compatibility before retrying

If the previous run failed with `INVALID FW PACKAGE`, the BFB version is
incompatible with the BMC firmware generation. Check the BMC firmware once
the DPU BMC has its lease back:

```bash
curl -sk -u root:'<dpu-bmc-pw>' \
  https://<DPU-BMC-IP>/redfish/v1/Managers/Bluefield_BMC/ \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('BMC FW:', d.get('FirmwareVersion'))"
```

Match against `pxe/Makefile.toml`:

| BMC `FirmwareVersion` | Required BFB DOCA | `DOCA_VERSION` | `BFB_BUILD` | `BFB_RELEASE` |
|---|---|---|---|---|
| `BF-25.x` | DOCA 2.9.2 | `2.9.2` | `31` | `25.02` |
| `BF-24.x` | DOCA 2.8.0 | `2.8.0` | `11` | `24.04` |
| `BF-32.x` | DOCA 3.2.2 | `3.2.2` | `125` | `26.02` |

If versions don't match, rebuild the BFB (`cargo make build-boot-artifacts-bfb`)
and copy it into the carbide-pxe pod **before** letting Carbide retry — see
[`DPU-PROVISIONING-NX.md § INVALID FW PACKAGE`](DPU-PROVISIONING-NX.md#invalid-fw-package--bfbbmc-version-mismatch).

---

## Troubleshooting Quick Reference

> **Full troubleshooting guide with detailed fixes: [`DEBUG.md`](DEBUG.md)**

| Symptom | Likely cause | Fix |
|---|---|---|
| Cannot reach VMs | Jump host down or credentials wrong | `ssh root@10.17.48.50` — verify password `nutanix/4u` |
| MetalLB services `<pending>` | `eth0` not on 10G subnet, or AHV Forged Transmits disabled | Phase 0c, pin L2Advertisement to correct NIC |
| DHCP: only DISCOVER, no OFFER | Switch `ip helper-address` not set, or VIP not reachable | Phase 8; test: `arping -I eth0 172.16.0.85` from any VM |
| PXE 404 | BMC MAC not in `expected_machines.json` | `ncli em list`, re-run Phase 9c |
| PXE connection refused | `carbide-pxe` pod not running or VIP unassigned | `kubectl get pods,svc -n forge-system` |
| Scout can't reach carbide-api | Route from `172.16.0.0/24` to `172.16.0.89` missing | Verify `eth0` route on all VMs: `ip route \| grep 172.16.0` |
| carbide-api CrashLoopBackOff | siteConfig TOML parse error (empty prefix/gateway) | `kubectl logs -n forge-system -l app.kubernetes.io/name=carbide-api --previous` |
| Machine stuck in Discovering | BMC not reachable from carbide-bmc-proxy pod | `kubectl exec -n forge-system -l app.kubernetes.io/name=carbide-bmc-proxy -- curl -sk https://<bmc-ip>/redfish/v1` |
| kubeadm join fails | Token expired (>24h) | `kubeadm token create --print-join-command` on VM1 |
| DevSpace build fails | Docker not running or disk full | `docker ps`; `df -h /var/lib/docker` |
| arping no reply on `172.16.0.85` | AHV Forged Transmits disabled on 10G vSwitch | Re-run Phase 0c; `acli net.update <net> ip_config.allow_ip_override=true` |
| `calico-node` 0/1 — BIRD not ready / connection refused | Two NICs cause ambiguous IP autodetection; BIRD binds wrong interface | `kubectl set env daemonset/calico-node -n kube-system IP_AUTODETECTION_METHOD=interface=eth0 IP6_AUTODETECTION_METHOD=none` — see Phase 2d |
| Felix: `lookup localhost on 8.8.8.8:53: i/o timeout` | NICo VM hostnames and `localhost` missing from `/etc/hosts` — OS falls through to unreachable `8.8.8.8` DNS | Add `127.0.0.1 localhost` and all `172.16.0.8x nico-*` entries to `/etc/hosts` on every node, then `kubectl rollout restart daemonset/calico-node -n kube-system` — see Phase 2d and Phase 0d Step 7 |

---

## Component Reference

Brief description of every NICo/Carbide service, how it fits in the system, and which
other components it depends on or talks to.

---

### carbide-api

**What it does:** Central control-plane gRPC service. Owns the state machine for every
bare-metal machine (discovery → DPU init → host init → ready → wipe/release). Stores
all state in PostgreSQL. Exposes an mTLS/gRPC API consumed by the Scout agent on each
DPU, the admin CLI, and every other NICo service.

**VIP:** `172.16.0.89:443`

**Key responsibilities:**
- Hardware inventory (machines, interfaces, DPUs, firmware versions)
- IP address allocation — makes all DHCP lease decisions via gRPC (carbide-dhcp calls in per packet)
- Network segment management (`admin` / `172.16.0.0/24`, `reserve_first` controls pool start)
- Site explorer orchestration — schedules and interprets BMC Redfish exploration
- DPU state machine — drives BFB install, TPM attestation, DPF integration
- iPXE script rendering and OS provisioning workflow
- DNS record lifecycle — creates/removes A records via carbide-dns

**Talks to:** PostgreSQL (all persistent state), carbide-dhcp (called per DHCP Discover
via `DiscoverDhcp` RPC), carbide-dns (DNS CRUD), carbide-pxe (iPXE template data),
carbide-bmc-proxy (all Redfish calls routed through it), Scout agent on each DPU (mTLS
gRPC inbound on `:443`).

**Config knobs in `values.base.yaml`:** `[networks.admin]` prefix/gateway/`reserve_first`,
`dhcp_servers`, `[site_explorer]`, `[machine_state_controller]`.

---

### carbide-dhcp

**What it does:** DHCP server for bare-metal BMC discovery on the 10G / VLAN 101
network (`172.16.0.0/24`). Built on **Kea DHCPv4** with a custom Rust callout hook
(`libdhcp.so`) that intercepts every packet and delegates all IP allocation decisions
to carbide-api via gRPC. Kea itself never chooses an IP — the hook does.

**VIP:** `172.16.0.85:67/UDP`

**Key responsibilities:**
- Receives relayed DHCP Discovers forwarded by the 10G switch (`ip helper-address 172.16.0.85`)
- Requires `giaddr != 0.0.0.0` — drops any non-relayed packet
- Calls carbide-api `DiscoverDhcp(mac_address, relay_address)` per Discover
- Returns DHCPOFFER with IP, subnet, gateway, DNS server, PXE next-server options
- Caches responses in memory to reduce API round-trips on retransmits

**Talks to:** carbide-api (one gRPC call per DHCP Discover), 10G switch (receives
relayed UDP/67 packets from BMC NICs).

**Key log messages to know:**

| Log | Meaning |
|-----|---------|
| `Packet type name: DHCPDISCOVER` | Relay packet accepted (`giaddr` set) |
| `Received a non-relayed packet, dropping it` | `giaddr = 0.0.0.0` — use relay or test script |
| `No network segment defined for relay addresses` | carbide-api has no segment for the `giaddr` subnet |
| `DHCP4_LEASE_ADVERT … lease 172.16.0.x` | IP allocated, OFFER being sent |
| `returning cached response` | Retransmit — served from in-memory cache |
| `Missing option [60] / [93]` | Vendor class / client arch absent — benign during testing |

**Test tool:** `dev/tools/dhcp_relay_test.py` — simulates a relayed Discover, no extra
dependencies.

---

### carbide-pxe

**What it does:** HTTP server that delivers iPXE boot artifacts (chainload scripts,
kernels, initrds, OS images) to bare-metal machines during PXE boot. carbide-api
renders the per-machine iPXE script based on the machine's state and assigned OS;
carbide-pxe serves it.

**VIPs:** `172.16.0.86:80/TCP` (PXE next-server, pointed to by DHCP OFFER),
`172.16.0.86:8080/TCP` (internal metrics/health)

**Key responsibilities:**
- Serves iPXE chainload scripts keyed by machine MAC or UUID
- Serves OS installer artifacts (kernel, initrd, preseed/kickstart)
- Calls carbide-api to resolve which script/OS to serve per machine

**Talks to:** carbide-api (iPXE template resolution per request), bare-metal BMC NICs
(HTTP GET during PXE boot), carbide-dhcp (DHCP OFFER includes `next-server = 172.16.0.86`
so BMC knows where to fetch iPXE).

**Failure mode:** Returns 404 if MAC is not in `expected_machines.json` or has no
assigned OS image.

---

### carbide-dns

**What it does:** Authoritative DNS server for **tenant/VPC dynamic records** —
backed by the NICo API + Postgres rather than a static zone file. Automatically
creates and removes DNS A records as machines are discovered, assigned IPs, and
released. Two replicas for redundancy.

**VIPs:** `172.16.0.87:53` and `172.16.0.88:53` (UDP + TCP)

> **What `carbide-dns` does NOT serve:** the static `.forge` zone
> (`carbide-pxe.forge`, `carbide-api.forge`, etc.). Those records live in
> `forge-unbound` (`172.16.0.91`). See the [unbound](#unbound) entry below for
> the rationale, and [DPU-PROVISIONING-NX.md § Why a dedicated unbound](DPU-PROVISIONING-NX.md#why-a-dedicated-unbound-instead-of-reusing-carbide-dns)
> for a deeper write-up.

**Key responsibilities:**
- Serves A records for machine hostnames (e.g. `172-16-0-20.local.forge → 172.16.0.20`)
- Serves per-VPC dynamic records on behalf of NICo tenants
- Receives record CRUD from carbide-api over gRPC as machines change state

**Talks to:** carbide-api (receives DNS record updates), managed hosts and DPU
in-band agents (DNS clients for tenant zones), upstream resolvers for
recursion via forge-unbound when configured.

---

### carbide-bmc-proxy

**What it does:** Authenticated mTLS reverse-proxy between carbide-api and physical BMC
Redfish endpoints. carbide-api never speaks directly to BMCs — all Redfish traffic goes
through this proxy, which injects BMC credentials from the credential store. This
keeps raw BMC passwords out of carbide-api's process.

**Port:** Internal ClusterIP only — `carbide-bmc-proxy.forge-system.svc.cluster.local:1079`.
No external VIP.

**Key responsibilities:**
- Proxies Redfish HTTP/HTTPS requests from carbide-api to BMC IPs
- Injects per-machine BMC credentials (Basic Auth header) from the DB
- Enforces mTLS on the carbide-api → proxy leg (SPIFFE/X.509 identity)
- In DevSpace lab mode: routes to `machine-a-tron-bmc-mock` instead of real hardware

**Talks to:** carbide-api (receives proxy requests inbound), physical BMC IPs (outbound
Redfish), machine-a-tron (lab only).

---

### carbide-hardware-health

**What it does:** Polls hardware health telemetry (GPU, NIC, CPU, memory, thermals)
from machines via Redfish and IPMI. Reports health events and alerts to carbide-api.
Does not affect the provisioning state machine directly.

**Port:** Internal ClusterIP only (`9009/TCP`).

**Talks to:** carbide-api (reports health data), carbide-bmc-proxy (Redfish polling),
physical BMC hardware (IPMI/Redfish endpoints).

---

### carbide-ssh-console (carbide-ssh-console-rs)

**What it does:** SSH serial-console gateway. Lets operators open an interactive serial
console to a bare-metal machine's BMC via standard SSH, without needing direct
BMC network access.

**VIP:** `172.16.0.90:22/TCP` (when enabled)

**Talks to:** carbide-api (machine credential lookup), physical BMC serial-over-LAN
endpoints.

> **Lab status:** Disabled by default — `carbide-ssh-console-rs.enabled: false` in
> `values.base.yaml`.

---

### unbound (forge-unbound)

**What it does:** Recursive DNS resolver that **hosts the static `.forge`
zone** consumed by BMCs on the OOB management network, and forwards anything
else to upstream public resolvers (`8.8.8.8`, `1.1.1.1` by default).

**VIP:** `172.16.0.91:53` (UDP + TCP) — advertised by `carbide-dhcp` to every
BMC as `carbide-nameservers` (DHCP option 6).

**Key responsibilities:**
- Resolves the names hardcoded in NICo binaries and Redfish `ImageURI` values:
  - `carbide-pxe.forge` → `172.16.0.86` (Redfish BFB transfer host)
  - `carbide-static-pxe.forge` → `172.16.0.86`
  - `carbide-api.forge` → `172.16.0.89`
  - `carbide-ntp.forge` → `172.16.0.80`
  - `unbound.forge` → `172.16.0.91`
- Forwards external queries (anything outside `.forge`) to public DNS
- Records are seeded from `localConfig.local_data.conf` in `values.base.yaml`

**Why not reuse `carbide-dns`?** `carbide-dns` only serves dynamic
tenant/VPC records sourced from the NICo API — it does not (and cannot
without invasive changes) host the static `.forge` zone needed during
Redfish BFB install, when no tenant context exists yet. See
[DPU-PROVISIONING-NX.md § Why a dedicated unbound](DPU-PROVISIONING-NX.md#why-a-dedicated-unbound-instead-of-reusing-carbide-dns).

**Talks to:** BMCs and DPU agents on the OOB network (DNS queries inbound),
upstream public DNS (e.g. `8.8.8.8`) for non-`.forge` recursion.

> **Lab status:** Disabled — `unbound.enabled: false`. External DNS is provided by the
> lab resolver at `172.16.0.50`.

carbide-dns (.87/.88) is an API-driven, authoritative server for per-tenant / per-VPC instance records. It's populated dynamically by NICo. It does not host the static infrastructure .forge zone and it isn't a general recursive resolver.
unbound (.90/.91) is a recursive resolver that (a) serves the static .forge infra zone (carbide-pxe.forge, carbide-api.forge, carbide-ntp.forge…) and (b) forwards everything else upstream (8.8.8.8/1.1.1.1). BMCs and DPUs need this during BFB install and cloud-init.

**Can you use an external/site DNS in production instead of unbound? Yes. unbound is just the batteries-included default so a greenfield site works without existing infra. To swap in your own resolver:

Point DHCP at it — set carbide-nameservers (the keaConfigJson hook param, line 199) to your DNS server IP instead of .90/.91.
Add the .forge A-records to that server, matching your VIPs:
carbide-api.forge → 172.16.0.89
carbide-pxe.forge → 172.16.0.86
carbide-static-pxe.forge → 172.16.0.86
carbide-ntp.forge → 172.16.0.80
Ensure it can recurse/forward for any non-.forge names the DPU needs.
Then set unbound.enabled: false.
---

### machine-a-tron (DevSpace lab only)

**What it does:** Mock BMC that simulates Redfish endpoints for local development and
integration testing without real physical hardware. carbide-bmc-proxy and
carbide-api's site-explorer point to it instead of real BMCs.

**Address:** `machine-a-tron-bmc-mock.forge-system.svc.cluster.local:1266`

**Talks to:** carbide-bmc-proxy (receives proxied Redfish calls from carbide-api).

> Not deployed in production. Controlled by `bmc_proxy` in `[site_explorer]` config.

---

## Container Image Licenses

License attribution for every container image deployed (or built) by this guide.
NICo's own code is **Apache-2.0** (see [`LICENSE`](LICENSE)); the images below also
bundle third-party software and base images that carry their own licenses. Use this
table when producing an SBOM or completing supply-chain / open-source compliance review.

### NICo / Carbide service images (built from this repo)

These images are produced from this repository by DevSpace (`Dockerfile.all-services`,
`Dockerfile.bmc-proxy`, `Dockerfile.machine-a-tron`). The NICo binaries they ship are
**Apache-2.0**; the table also lists the OS base image and any notable embedded
third-party runtime component.

| Image / component | NICo code license | Base image | Notable bundled software (license) |
|-------------------|-------------------|------------|------------------------------------|
| `carbide-api` | Apache-2.0 | `debian:bookworm-slim` (via `carbide-runtime-base`) | Debian runtime libs (mixed GPL/LGPL/MIT/BSD) |
| `carbide-pxe` (`carbide`) | Apache-2.0 | `debian:bookworm-slim` (via `carbide-runtime-base`) | Debian runtime libs (mixed GPL/LGPL/MIT/BSD) |
| `carbide-dns` | Apache-2.0 | `debian:bookworm-slim` (via `carbide-runtime-base`) | Debian runtime libs (mixed GPL/LGPL/MIT/BSD) |
| `carbide-dhcp` (`forge-dhcp-server` + `libdhcp.so`) | Apache-2.0 | `debian:bookworm-slim` (via `carbide-runtime-base`) | **ISC Kea DHCPv4 — MPL-2.0** (the Rust callout hook links against Kea) |
| `carbide-hardware-health` (`forge-hw-health`) | Apache-2.0 | `debian:bookworm-slim` (via `carbide-runtime-base`) | Debian runtime libs (mixed GPL/LGPL/MIT/BSD) |
| `carbide-ssh-console` | Apache-2.0 | `debian:bookworm-slim` (via `carbide-runtime-base`) | Debian runtime libs (mixed GPL/LGPL/MIT/BSD) |
| `carbide-bmc-proxy` | Apache-2.0 | `ubuntu:24.04` | Ubuntu runtime libs (mixed GPL/LGPL/MIT/BSD) |
| `machine-a-tron` (lab only) | Apache-2.0 | `debian:bookworm-slim` | Debian runtime libs (mixed GPL/LGPL/MIT/BSD) |

> The `carbide-runtime-base` image (`Dockerfile.runtime-base`) installs
> `kea-dhcp4-server` / `kea-ctrl-agent` from Debian. ISC Kea is licensed under the
> **Mozilla Public License 2.0 (MPL-2.0)** — <https://github.com/isc-projects/kea/blob/master/COPYING>.

### Site-built dependency images

Rebuilt locally so the supply chain is owned by the deploying site (they replace the
upstream `nvcr.io/nvidian/nvforge/*` images). The upstream software keeps its original
license; the build recipe (the Dockerfile) is Apache-2.0.

| Image | Upstream project | Upstream license | Base image |
|-------|------------------|------------------|------------|
| `forge/unbound` | [NLnetLabs Unbound](https://github.com/NLnetLabs/unbound) | **BSD-3-Clause** — <https://github.com/NLnetLabs/unbound/blob/master/LICENSE> | `ubuntu:24.04` |
| `forge/unbound_exporter` | [letsencrypt/unbound_exporter](https://github.com/letsencrypt/unbound_exporter) | Apache-2.0 | `gcr.io/distroless/static:nonroot` (Apache-2.0) |

> The `forge/unbound` image already declares `org.opencontainers.image.licenses="BSD-3-Clause"`
> and `forge/unbound_exporter` declares `Apache-2.0` via OCI labels, so image scanners
> attribute them automatically.

### Third-party prerequisite images (pulled, not built)

Pulled as-is during bootstrap (cert-manager, Postgres, Vault) and cluster setup
(Calico, MetalLB, CoreDNS). NICo does not modify or redistribute these images.

| Image | Version | License |
|-------|---------|---------|
| `postgres` (Docker Hub) | `14.5-alpine` | PostgreSQL License (permissive, BSD-like); Alpine base is MIT/BSD with BusyBox under GPL-2.0 |
| `hashicorp/vault` (Docker Hub) | `1.20.2` | **BUSL-1.1** (Business Source License — source-available; internal/non-compete production use permitted, converts to MPL-2.0 after the change date) |
| `quay.io/jetstack/cert-manager-controller` | `v1.15.3` | Apache-2.0 |
| `quay.io/jetstack/cert-manager-cainjector` | `v1.15.3` | Apache-2.0 |
| `quay.io/jetstack/cert-manager-webhook` | `v1.15.3` | Apache-2.0 |
| `quay.io/jetstack/cert-manager-startupapicheck` | `v1.15.3` | Apache-2.0 |
| Calico CNI (`docker.io/calico/*`) | per `calico.yaml` | Apache-2.0 |
| MetalLB (`quay.io/metallb/*`) | chart `0.14.5` | Apache-2.0 |
| CoreDNS (kubeadm-managed) | per k8s `v1.30.4` | Apache-2.0 |
| `rust` (build base only — not shipped at runtime) | `1.90.0-slim-bookworm` | Rust toolchain: MIT OR Apache-2.0; `debian:bookworm-slim` base |

> **Vault note:** `hashicorp/vault:1.20.2` is **not** OSI open source — it ships under
> the Business Source License 1.1. Running it for the cluster's own internal secret
> management (as this guide does) is permitted; offering a competing hosted/embedded
> Vault service is not. Confirm with your legal/compliance team before redistribution.

---

## Component Interaction Map

```
                    ┌──────────────────────────────────────────────┐
                    │            carbide-api (172.16.0.89:443)     │
                    │  state machine · IPAM · DNS · Redfish        │
                    │  orchestration · iPXE · firmware · DPU init  │
                    └────┬────────┬────────┬─────────┬─────────────┘
                         │        │        │         │
           ┌─────────────┘        │        │         └──────────────────┐
           │                      │        │                            │
           ▼                      ▼        ▼                            ▼
 ┌──────────────────┐  ┌──────────────┐ ┌──────────────┐  ┌──────────────────────┐
 │  carbide-dhcp    │  │ carbide-pxe  │ │ carbide-dns  │  │  carbide-bmc-proxy   │
 │  172.16.0.85:67  │  │ 172.16.0.86  │ │ .87/.88 :53  │  │  (internal only)     │
 │  Kea + Rust hook │  │ :80 / :8080  │ │ authoritative│  │  Redfish proxy +     │
 │  DHCP relay srv  │  │ iPXE + OS    │ │ local.forge  │  │  credential injector │
 └────────┬─────────┘  └──────┬───────┘ └──────────────┘  └──────────┬───────────┘
          │ giaddr             │ HTTP GET                              │ Redfish HTTP
          ▼                    │                                       ▼
 ┌─────────────────┐           │                           ┌──────────────────────┐
 │  10G Switch     │           │                           │  BMC Redfish API     │
 │  VLAN 101       │           │                           │  (or machine-a-tron  │
 │  ip helper-addr │           │                           │   in DevSpace lab)   │
 │  → 172.16.0.85  │           │                           └──────────────────────┘
 └────────┬────────┘           │
          │ relay              │ PXE next-server
          ▼                    ▼
 ┌──────────────────────────────────────────┐
 │  BMC NIC   (gets 172.16.0.20–.76)        │
 │  PXE boots → fetches iPXE from .86:80    │
 └───────────────────┬──────────────────────┘
                     │ Scout agent  (mTLS gRPC, inbound to carbide-api:443)
                     ▼
          ┌─────────────────────┐
          │  DPU (BlueField ARM)│
          │  Scout OS           │
          └─────────────────────┘

  Supporting infrastructure:
  ┌──────────┐  ┌───────────┐  ┌─────────┐  ┌──────────────────────┐
  │PostgreSQL│  │  MetalLB  │  │ Calico  │  │  Kubernetes (kubeadm)│
  │ state DB │  │ VIP announ│  │ pod net │  │  3 nodes (1cp+2wkr)  │
  └──────────┘  └───────────┘  └─────────┘  └──────────────────────┘
```

**Typical BMC discovery data flow (numbered steps):**

1. BMC NIC powers on → broadcasts DHCP Discover on VLAN 101
2. 10G switch relays Discover to `172.16.0.85` (sets `giaddr = switch SVI IP`)
3. carbide-dhcp receives Discover → calls carbide-api `DiscoverDhcp(mac, giaddr)`
4. carbide-api looks up MAC in expected machines → allocates IP from `172.16.0.20+`
5. carbide-dhcp sends DHCPOFFER → BMC gets IP (e.g. `172.16.0.20`) + `next-server = 172.16.0.86`
6. carbide-api creates DNS A record `172-16-0-20.local.forge` via carbide-dns
7. BMC PXE boots → fetches iPXE chainload script from `carbide-pxe` at `172.16.0.86:80`
8. carbide-api site-explorer → connects to BMC Redfish via carbide-bmc-proxy → reads hardware inventory
9. DPU receives BFB image → boots Scout OS → connects to `carbide-api:443` via mTLS
10. carbide-api advances state machine: `Discovering → DpuInit → HostInit → Ready`

---

## Post-Discovery: DPU PXE Boot and State Machine Walkthrough

Once both BMCs are discovered and `ncli machine show` shows `DPUINITIALIZING/INIT`,
NICo drives the DPU PXE boot **automatically** via Redfish. No manual iPXE/boot triggers
are needed under normal conditions. This section documents what happens and how to
diagnose if the machine gets stuck.

### What NICo Does Automatically in `DPUINITIALIZING/INIT`

```
DPUINITIALIZING/INIT
    │
    │  1. Waits for DPU scout to report (last_discovery_time set)
    │     If not yet reported → triggers DPU reboot via Redfish ForceRestart
    │     DPU reboots → PXE boot → carbide.efi (ARM) → scout reports back
    │
    │  2. All DPUs discovered → sets boot_once(UefiHttp) on DPU BMC Redfish
    │     Then issues ForceRestart on DPU BMC
    ▼
DPUINITIALIZING/WaitingForPlatformPowercycle (Off)
    │  - Waits for all DPUs to reach powered-off state
    │  - Powers OFF host chassis via host BMC Redfish
    ▼
DPUINITIALIZING/WaitingForPlatformPowercycle (On)
    │  - Waits power_down_wait timeout
    │  - Powers ON host chassis via host BMC Redfish (PCIe bus reinit for DPU)
    ▼
DPUINITIALIZING/WaitingForPlatformConfiguration
    │  - Verifies DPU NIC mode and configuration via Redfish
    ▼
DPUINITIALIZING/InstallDpuOs
    │  - Installs BF-bundle (carbide.efi + carbide.root) via HTTP boot
    ▼
HostInit → Ready
```

> **Key point:** During `WaitingForPlatformPowercycle`, NICo calls Redfish on the
> **host BMC** (`172.16.0.20`) to power cycle the chassis. Both the host BMC and DPU BMC
> must be reachable at this stage.

---

### Monitoring State Machine Progress

```bash
# Watch machine state every 30 seconds
watch -n 30 ncli machine show

# Stream carbide-api logs filtered to DPU state transitions
kubectl logs -f -n forge-system deployment/carbide-api \
  | grep -E "DPU|dpu|restart|reboot|discovery|Init|WaitingForPlatform"

# Check site-explorer endpoint report for exploration status
ncli site-explorer get-report endpoint

# Check carbide-pxe logs to confirm PXE requests are being served
kubectl logs -f -n forge-system deployment/carbide-pxe
```

---

### Verifying BMC Reachability (Prerequisites for Automatic Flow)

NICo uses Redfish for all power control. Verify both BMCs respond before the state
machine advances:

```bash
# Host BMC (required for chassis power cycle during DPUInit)
curl -k -u root:'<host-bmc-password>' https://172.16.0.20/redfish/v1/Systems/1

# DPU BMC (required for DPU reboot and boot_once)
curl -k -u root:'nutanix/4u' https://172.16.0.23/redfish/v1/Systems/Bluefield
```

---

### Manual PXE Boot Trigger (If Stuck at `DPUINITIALIZING/INIT`)

If the state machine is stuck and the DPU is not being rebooted automatically
(e.g. due to a transient Redfish error), you can manually trigger PXE boot on the
DPU BMC:

```bash
# Set next one-time boot to PXE/HTTP, then power cycle
ipmitool -I lanplus -H 172.16.0.23 -U root -P 'nutanix/4u' \
  chassis bootdev pxe options=efiboot

ipmitool -I lanplus -H 172.16.0.23 -U root -P 'nutanix/4u' power cycle
```

> Use `power cycle` (hard off → on) rather than `power reset` if the DPU is stuck.
> `power reset` is a warm reset and may not clear a hung state.

After the manual reboot, `carbide-pxe` should serve `carbide.efi` to the DPU's MAC
address (`84:EB:0C:5B:59:8C` / `84:EB:0C:5B:59:9C`) and the state machine will advance.

---

### Expected `ncli machine show` Progression

| State | Meaning |
|---|---|
| `DPUINITIALIZING/INIT` | Waiting for DPU scout to report; will trigger reboot |
| `DPUINITIALIZING/WaitingForPlatformPowercycle` | Host chassis being power cycled via host BMC |
| `DPUINITIALIZING/WaitingForPlatformConfiguration` | Verifying DPU Redfish config |
| `DPUINITIALIZING/InstallDpuOs` | Installing BF-bundle (BFB) on DPU |
| `HostInit/WaitingForPlatformConfiguration` | DPU done; host awaiting Scout OS boot |
| `Ready` | Fully managed — available for tenant provisioning |

---

### Understanding the Two Machine Records

When `ncli machine show` returns two rows for one physical host+DPU, this is expected:

| Type | MAC | IP | Role |
|---|---|---|---|
| `DPU` | `84:EB:0C:5B:59:B0` (`oob0`) | `172.16.0.24` | DPU machine record (underlay/BMC OOB) |
| `Host (Predicted)` | `84:EB:0C:5B:59:8C` (base/PF0) | `172.16.10.20` | Proactive host record (admin/inband) |

- The **DPU** record is the real DPU BMC as explored by site-explorer.
- The **Host (Predicted)** record is created proactively by NICo from the DPU's
  `base_mac` Redfish field, anchored to the `admin` network segment (`172.16.10.0/24`).
  It will be upgraded to a full `Host` record once Scout OS reports in.
- `172.16.0.24` (MAC `:B0` / `oob0`) is the DPU's rshim/OOB host-facing interface that
  sent a DHCP discover on the BMC management network — this is normal BlueField
  behaviour and does not conflict with the DPU BMC management IP `172.16.0.23` (MAC `:B1`).

---

### Required Network Segments for Full Operation

Both segments must exist in the database (verify with `SELECT name, network_segment_type FROM network_segments;`):

| Segment name | Type | Prefix | Purpose |
|---|---|---|---|
| `admin` | `underlay` | `172.16.0.0/24` | BMC OOB discovery, DHCP for BMC NICs |
| `host-inband` | `admin` | `172.16.10.0/24` | Host inband — proactive host interface anchor |

If `host-inband` is missing after a fresh deploy, restart `carbide-api`:

```bash
kubectl rollout restart deployment/carbide-api -n forge-system
kubectl rollout status deployment/carbide-api -n forge-system
# Look for: "Created network segment host-inband"
kubectl logs -n forge-system deployment/carbide-api | grep "network segment"
```

If it says `Network segment host-inband exists` but the DB query shows wrong type,
delete the stale segment (see [DEBUG.md](DEBUG.md)) then restart.

---

## Phase 11 — Build DPU Boot Artifacts (`forge.bfb`)

> **Why this is needed:** NICo provisions DPUs with a custom BFB that embeds
> `forge-dpu-agent`. The stock DOCA BFB from developer.nvidia.com does **not**
> include this agent. The DPU state machine (`WaitingForNetworkConfig`) cannot
> advance without it.
>
> **Air-gap requirement:** Several binaries must be pre-staged on `nico-cp-1`
> before running the build (see [Pre-Stage All Required Files](#pre-stage-all-required-files-run-once-on-jump-host)).

### 11a. Install host system packages on `nico-cp-1`

The build requires several system packages on the host machine (not inside
Docker). Install them once before running `cargo make build-boot-artifacts-bfb`:

```bash
apt-get update
apt-get install -y \
  python3 \        # runs mlx-mkbfb (BFB extract/repack tool)
  cpio \           # extracts and repacks BFB initramfs
  pigz \           # parallel gzip for fast initramfs recompression
  xz-utils \       # decompresses LZMA-compressed EFI kernel (bfb-copy-efi task)
  file \           # detects LZMA compression on EFI kernel (bfb-copy-efi task)
  wget \           # downloads BFB, mlx-mkbfb, and other artifacts
  docker.io \      # cross-compile container + HBN container pull
  dpkg-dev \       # dpkg-scanpackages — builds apt repo index (setup-apt-repo-arm64)
  openssl \        # extracts secure-boot PK cert from BFB (add-secure-boot-pk-pem)
  patch \          # applies iPXE patches (ipxe-patch-* tasks)
  make \           # builds iPXE EFI kernel (ipxe-build-efi-aarch64)
  gcc \            # required by iPXE build system
  binutils \       # provides ld, objcopy used by iPXE build
  git              # git describe for DPU_AGENT_PKG_VERSION and IPXE_BANNER_VERSION
```

> **Package-to-task mapping:**
>
> | Package | Which task needs it | Why |
> |---|---|---|
> | `python3` | `bfb-extract`, `bfb-create-bfb` | runs `mlx-mkbfb` BFB extract/repack script |
> | `cpio` | `bfb-extract-efi`, `bfb-rebuild-rootfs` | extract/repack initramfs |
> | `pigz` | `bfb-rebuild-rootfs` | parallel gzip for initramfs compression |
> | `xz-utils` | `bfb-copy-efi` | decompress LZMA-compressed EFI kernel |
> | `file` | `bfb-copy-efi` | detect if EFI kernel is LZMA-compressed |
> | `wget` | `bfb-download`, `bfbtools-download`, `download-debs-for-bfb` | downloads BFB and dependencies |
> | `docker.io` | `build-cross-docker-image`, `bfb-hbn-pull`, `bfb-hbn-export` | cross-compile container + HBN image |
> | `dpkg-dev` | `setup-apt-repo-arm64` | `dpkg-scanpackages` to build apt package index |
> | `openssl` | `add-secure-boot-pk-pem` | convert DER cert to PEM for secure boot |
> | `patch` | `ipxe-patch-mlnx`, `ipxe-patch-grace-grace`, `ipxe-patch-efi-rng`, `ipxe-patch-measured-boot`, `ipxe-patch-watchdog-timeout` | apply iPXE source patches |
> | `make` | `ipxe-build-efi-aarch64` | compile iPXE EFI kernel |
> | `gcc`, `binutils` | `ipxe-build-efi-aarch64` | toolchain for iPXE build system |
> | `git` | env var computation (`DPU_AGENT_PKG_VERSION`, `IPXE_BANNER_VERSION`) | version strings from git tags |
>
> The following are provided **inside the cross-compile Docker container**
> (`build-artifacts-container-cross-aarch64`) and do **not** need to be
> installed on the host:
>
> | Package (Docker only) | Purpose |
> |---|---|
> | `g++-aarch64-linux-gnu` | ARM64 C/C++ cross-compiler |
> | `libudev-dev:arm64` | `carbide-agent` cross-compile dependency |
> | `libssl-dev:arm64` | OpenSSL ARM64 headers |
> | `libtss2-dev:arm64` | TPM2 library ARM64 headers |
> | `libc6-dev-arm64-cross` | ARM64 libc headers |
> | `libclang-dev`, `cmake` | bindgen and C++ build support |
> | `protoc` (protobuf v3.15.8) | protobuf compiler for gRPC code generation |
> | Rust `aarch64-unknown-linux-gnu` target | cross-compile Rust to ARM64 |

Also install `cargo-make` if not already present (needed to run build tasks):

```bash
cargo install cargo-make
```

### 11b. Pre-stage binaries on `nico-cp-1`

After copying from the jump host, extract binaries into the expected locations
so the build skips the download steps:

```bash
cd ~/nurametal/infra-controller-core   # or wherever the repo lives

# Compute the version tag used for the deb package directory name
VER=$(git describe --tags --first-parent --always --long | cut -c 2-)
BIN=bluefield/forge-dpu_${VER}_arm64/usr/bin
LIC=bluefield/forge-dpu_${VER}_arm64/usr/share/licenses
mkdir -p $BIN $LIC/node_exporter $LIC/transceiver-exporter

# node-exporter
cp ~/staged/node_exporter-1.8.2.linux-arm64.tar.gz bluefield/node_exporter/
cd bluefield/node_exporter/
tar xzf node_exporter-1.8.2.linux-arm64.tar.gz
cp node_exporter-1.8.2.linux-arm64/node_exporter ../../$BIN/
cp node_exporter-1.8.2.linux-arm64/LICENSE ../../$LIC/node_exporter/
rm -rf node_exporter-1.8.2.linux-arm64
cd ../../

# transceiver-exporter
cp ~/staged/transceiver-exporter-v1.5.0-linux-arm64.tar.gz bluefield/transceiver_exporter/
cd bluefield/transceiver_exporter/
tar xzf transceiver-exporter-v1.5.0-linux-arm64.tar.gz
cp transceiver-exporter-v1.5.0-linux-arm64/transceiver-exporter ../../$BIN/
cp transceiver-exporter-v1.5.0-linux-arm64/LICENSE.md ../../$LIC/transceiver-exporter/
rm -rf transceiver-exporter-v1.5.0-linux-arm64
cd ../../

# Go toolchain (for building otelcol-contrib — only needed if otelcol-contrib
# hasn't been built before)
cp ~/staged/go1.22.0.linux-amd64.tar.gz bluefield/otel/
cd bluefield/otel/
tar xzf go1.22.0.linux-amd64.tar.gz   # extracts to bluefield/otel/go/
rm go1.22.0.linux-amd64.tar.gz
cd ../../
```

Also ensure the stock DOCA BFB is pre-staged. The expected filename is determined
by the version variables in `pxe/Makefile.toml` (see [Switching DOCA versions](#11g-switching-doca-versions-for-different-bmc-firmware)):

```bash
# Check which BFB the build expects (reads current Makefile.toml values):
cd ~/nurametal/infra-controller-core
DOCA_VERSION=$(grep '^DOCA_VERSION' pxe/Makefile.toml | cut -d'"' -f2)
BFB_BUILD=$(grep '^BFB_BUILD' pxe/Makefile.toml | cut -d'"' -f2)
BFB_RELEASE=$(grep '^BFB_RELEASE' pxe/Makefile.toml | cut -d'"' -f2)
BFB_NAME="bf-bundle-${DOCA_VERSION}-${BFB_BUILD}_${BFB_RELEASE}_ubuntu-22.04_prod.bfb"
echo "Expected BFB: /tmp/bfb-dump/${BFB_NAME}"

# Check if BFB is already staged:
ls /tmp/bfb-dump/${BFB_NAME} 2>/dev/null || echo "BFB missing — scp from jump host"

# Check if mlx-mkbfb is available:
ls /tmp/bfb-dump/mlx-mkbfb 2>/dev/null || echo "mlx-mkbfb missing — will be downloaded"
```

### 11c. Set `SQUID_PROXY` and run the build

The build uses a Squid proxy (`172.16.0.50:3128`) for any remaining internet
access needed during the Docker cross-compile step and Go module downloads.

```bash
cd ~/nurametal/infra-controller-core/pxe

export SQUID_PROXY=http://172.16.0.50:3128
export CARGO_HOME=~/.cargo   # required by build-dpu-agent-and-dhcp-server task

cargo make build-boot-artifacts-bfb
```

> **What `SQUID_PROXY` controls in the build:**
>
> | Task | What it proxies |
> |---|---|
> | `bfb-download` | Stock BFB wget (skipped if file exists) |
> | `bfbtools-download` | `mlx-mkbfb` wget (skipped if file exists) |
> | `download-debs-for-bfb` | Debian package downloads inside Docker |
> | `download-go` | Go toolchain wget (skipped if `otel/go/` exists) |
> | `download-otelcol-builder` | `ocb` binary curl |
> | `download-node-exporter` | node-exporter wget (skipped if binary exists) |
> | `download-transceiver-exporter` | transceiver-exporter wget (skipped if binary exists) |
> | `build-cross-docker-image` | `apt-get` inside Docker for cross-compile toolchain |
>
> All download tasks check for file existence first and skip the network call
> if the file is already present — safe to re-run after partial failures.

### 11d. Verify build output

```bash
# Expected outputs after a successful build:
ls -lh pxe/static/blobs/internal/aarch64/
# forge.bfb        — full DPU OS image with forge-dpu-agent embedded
# carbide.efi      — DPU agent kernel (from BFB)
# carbide.root     — DPU agent initramfs (from BFB)
# scout.efi        — iPXE EFI bootloader

ls -lh pxe/static/blobs/internal/x86_64/
# ipxe.efi         — Host iPXE EFI bootloader
```

### 11e. Deploy boot artifacts to `carbide-pxe`

After a successful build, redeploy NICo so carbide-pxe picks up the new artifacts:

```bash
cd ~/nurametal/infra-controller-core
devspace deploy -n forge-system --force-deploy
```

Verify the files are served:

```bash
PXE_VIP=172.16.0.86
curl -s -o /dev/null -w "%{http_code}" http://${PXE_VIP}/blobs/internal/aarch64/forge.bfb
# Expected: 200
```

### 11e. Deploy boot artifacts to `carbide-pxe`

After a successful build, redeploy NICo so `carbide-pxe` picks up the new
artifacts (it bakes `static/blobs/` into the container image):

```bash
cd ~/nurametal/infra-controller-core
devspace deploy -n forge-system --force-deploy
```

Verify the file is served before proceeding:

```bash
PXE_VIP=172.16.0.86
curl -s -o /dev/null -w "%{http_code}\n" http://${PXE_VIP}/blobs/internal/aarch64/forge.bfb
# Expected: 200  (404 = deploy didn't pick up the file — check carbide-pxe pod restarted)
```

### 11f. Trigger DPU reprovisioning

Once `forge.bfb` is verified at HTTP 200, reset both machines in the DB. The
host machine must be reset to `Unmanaged` first — while it holds
`INSTALLATIONERROR` it keeps the DPU blocked from retrying.

```bash
# Open a psql shell into the DB
kubectl exec -n forge-system -it deployment/carbide-api -- \
  psql "${DATABASE_URL}"
```

```sql
-- 1. Reset HOST machine out of INSTALLATIONERROR → Created
--    (ManagedHostState serde tag is "state", rename_all = "lowercase")
UPDATE machines
SET controller_state         = '{"state":"created"}',
    controller_state_version = 'V1-T' || floor(EXTRACT(EPOCH FROM NOW()) * 1000000)::bigint,
    last_reboot_requested    = NULL,
    last_reboot_time         = NULL,
    last_discovery_time      = NULL
WHERE id = '<HOST_MACHINE_ID>';

-- 2. Reset DPU machine → DPUInit/Init (triggers fresh BFB install)
--    DpuInitState serde tag is "dpustate", rename_all = "lowercase"
--    The dpu_states map key is the DPU's own machine ID.
UPDATE machines
SET controller_state         = '{"state":"dpuinit","dpu_states":{"states":{"<DPU_MACHINE_ID>":{"dpustate":"init"}}}}',
    controller_state_version = 'V1-T' || floor(EXTRACT(EPOCH FROM NOW()) * 1000000)::bigint,
    last_reboot_requested    = NULL,
    last_reboot_time         = NULL,
    last_discovery_time      = NULL
WHERE id = '<DPU_MACHINE_ID>';
```

> **JSON format rules** — wrong JSON causes `missing field 'state'` deserialization
> errors in `ncli machine show`. The `ManagedHostState` enum uses
> `#[serde(tag = "state", rename_all = "lowercase")]` — the discriminant key is
> `"state"` and variant names are lowercased. The `DpuInitState` enum uses
> `#[serde(tag = "dpustate", rename_all = "lowercase")]`. Using `"type"` or any
> other key will break deserialization immediately.
>
> **Why reset the host too?** The host row carries the `INSTALLATIONERROR`
> substate from the previous failed Redfish push. NICo's state machine checks
> the host's state before initiating a new BFB install — leaving it in
> `INSTALLATIONERROR` blocks the retry even after the DPU row is reset.

Power-cycle the DPU via IPMI to ensure a clean BMC reset:

```bash
DPU_BMC_IP=<dpu_bmc_ip>
ipmitool -I lanplus -H ${DPU_BMC_IP} -U <bmc_user> -P <bmc_pass> power cycle
```

Monitor progression:

```bash
kubectl logs -n forge-system deployment/carbide-api -f \
  | grep -E "bfb|DPU|InstallingBFB|WaitingFor|InstallationError|SimpleUpdate"
```

Expected state progression:
```
DPUINITIALIZING/INIT
  → DPUINITIALIZING/INSTALLDPUOS { InstallingBFB }    ← Redfish SimpleUpdate started
  → DPUINITIALIZING/INSTALLDPUOS { WaitingForReboot } ← BMC accepted BFB, rebooting
  → DPUINITIALIZING/WAITINGFORNETWORKCONFIG            ← DPU booted forge.bfb, agent calling home
  → MANAGED                                            ← success
```

If you see `INSTALLATIONERROR` again after resetting:
- Confirm `forge.bfb` HTTP 200 (Step 11e verify command above)
- Confirm the BFB was built from the correct DOCA version (check `strings pxe/static/blobs/internal/aarch64/preingestion.bfb | grep -i "bf-bundle"`)
- Check `kubectl logs -n forge-system deployment/carbide-api | grep -i "invalid fw"` for the Redfish error detail

### 11g. Switching DOCA versions for different BMC firmware

The four variables at the top of `pxe/Makefile.toml` control which base BFB is
downloaded and used when building `forge.bfb`. Change them to match your
hardware's BMC firmware generation:

| BMC firmware prefix | DOCA version | `DOCA_VERSION` | `BFB_BUILD` | `BFB_RELEASE` | `DOCA_HBN_VERSION` | `DOCA_HBN_TAG` |
|---|---|---|---|---|---|---|
| `BF-25.x` (e.g. BF-25.10-15) | DOCA 2.9.2 | `"2.9.2"` | `"31"` | `"25.02"` | `"2.4.2"` | `"2.4.2-doca2.9.2-32"` |
| `BF-24.x` | DOCA 2.8.0 | `"2.8.0"` | `"11"` | `"24.04"` | `"2.3.0"` | `"2.3.0-doca2.8.0"` |
| `BF-32.x` (newer) | DOCA 3.2.2 | `"3.2.2"` | `"125"` | `"26.02"` | `"3.2.2"` | `"3.2.2-doca3.2.2"` |

The BFB filename is constructed as:
```
bf-bundle-<DOCA_VERSION>-<BFB_BUILD>_<BFB_RELEASE>_ubuntu-22.04_prod.bfb
```

**Step-by-step to switch to a different firmware generation:**

1. Edit `pxe/Makefile.toml` — update the five variables:
   ```toml
   DOCA_VERSION     = "2.9.2"              # ← target DOCA version
   BFB_BUILD        = "31"                  # ← matching build number
   BFB_RELEASE      = "25.02"              # ← matching release tag
   DOCA_HBN_VERSION = "2.4.2"             # ← HBN resource version (NGC API key)
   DOCA_HBN_TAG     = "2.4.2-doca2.9.2-32" # ← exact NGC container image tag
   ```
   > **Finding `DOCA_HBN_TAG`:** Download NVIDIA's official `doca_hbn.yaml` for the
   > target HBN version and check the `image:` field:
   > ```bash
   > curl -s "https://api.ngc.nvidia.com/v2/resources/org/nvidia/team/doca/doca_hbn/<HBN_VERSION>/files" \
   >   | python3 -c "import sys,json; d=json.load(sys.stdin); [print(u) for fp,u in zip(d['filepath'],d['urls']) if 'doca_hbn.yaml' in fp]" \
   >   | xargs curl -s | grep 'image:'
   > ```

2. Update the expected firmware versions in `crates/api/src/cfg/file.rs`.
   After installing the new BFB once, retrieve the actual versions from the DPU:
   ```bash
   curl -sk -u ${BMC_USER}:${BMC_PASS} \
     "https://${DPU_BMC_IP}/redfish/v1/UpdateService/FirmwareInventory?\$expand=.(\$levels=1)" \
     | jq -c '.Members[] | select(.Id | test("^(BMC_Firmware|Bluefield_FW.*|DPU_UEFI|DPU_NIC)$")) | {Id, Version}'
   ```
   Then set `BF2_BMC`, `BF2_NIC`, `BF2_CEC`, `BF2_UEFI` (BF2) or `BF3_*` (BF3)
   constants in `file.rs` to match the reported versions.

3. Pre-stage the new BFB on `nico-cp-1`:
   ```bash
   mkdir -p /tmp/bfb-dump
   # scp or wget the new BFB to /tmp/bfb-dump/<BFB_NAME>
   ```

4. Rebuild:
   ```bash
   cd ~/nurametal/infra-controller-core/pxe
   export SQUID_PROXY=http://172.16.0.50:3128
   cargo make build-boot-artifacts-bfb
   ```

5. Redeploy and reset DPU state as described in [§11e](#11e-deploy-boot-artifacts-to-carbide-pxe)
   and [§11f](#11f-trigger-dpu-reprovisioning).

> **Why a rebuild is always required when switching firmware generations:**
> The BMC validates that the BFB version is compatible with the running BMC
> firmware before accepting a Redfish `SimpleUpdate`. A DOCA 3.2 BFB will be
> rejected with `INVALID FW PACKAGE` by a BF-25.x BMC, and vice versa. There
> is no runtime flag — the correct base BFB version must be baked into
> `forge.bfb` at build time.

---

## Section 12 — Production TLS / CA Certificate Reference

> **machine-a-tron is disabled in this lab** (`devspace.yaml` image + deployment both
> commented out). This section documents the **complete certificate chain** for
> production (`helm-prereqs` path) so that `carbide-admin-cli` works correctly
> from an operator workstation. machine-a-tron is a BMC hardware simulator only —
> it has no role in PKI or admin CLI authentication.

---

### 12a. Production PKI Chain (top-to-bottom)

```
cert-manager  (selfsigned-bootstrap ClusterIssuer — hook weight -10)
  └── site-root  Certificate  (10-year self-signed CA, hook weight -9)
        │  Stored in: Secret/site-root  in cert-manager namespace
        │
        ├── site-issuer  ClusterIssuer (hook weight -5)
        │     Issues Vault's own TLS certs BEFORE Vault starts:
        │       Secret/forgeca-vault-client  — Vault HTTPS listener (port 8200)
        │       Secret/vault-raft-tls        — Vault Raft peer cert (port 8201)
        │
        └── Vault PKI engine  ("forgeca" mount)
              site-root CA+key imported by vault-pki-config Job (hook weight 10)
                  │
                  └── vault-forge-issuer  ClusterIssuer (hook weight 15)
                        Issues ALL service SPIFFE mTLS certs via cert-manager:
                          Secret/carbide-api-certificate
                          Secret/carbide-bmc-proxy-certificate
                          Secret/carbide-dhcp-certificate
                          Secret/carbide-dns-certificate
                          Secret/carbide-pxe-certificate
                          Secret/carbide-hardware-health-certificate
                          (... all other services)

ESO (External Secrets Operator)
  ClusterExternalSecret/forge-roots-eso
    Source: site-root  Secret (cert-manager ns)  key: ca.crt
    Target: forge-roots Secret (forge-system ns)  key: ca.crt
      Mounted into carbide-api at /var/run/secrets/forge-roots/ca.crt

Admin CLI uses a SEPARATE out-of-band admin CA:
  deploy/files/carbide-api/admin_root_cert_pem
    Loaded by carbide-api as an additional trusted client-cert CA.
    If file is missing/unreadable → silently skipped → CLI certs rejected.
```

**Where each cert ends up in `carbide-api`:**

| Config field (`carbide-api-config.toml`) | Path in pod | Source |
|---|---|---|
| `identity_pemfile_path` | `/var/run/secrets/spiffe.io/tls.crt` | `Secret/carbide-api-certificate` |
| `identity_keyfile_path` | `/var/run/secrets/spiffe.io/tls.key` | `Secret/carbide-api-certificate` |
| `root_cafile_path` | `/var/run/secrets/spiffe.io/ca.crt` | `Secret/carbide-api-certificate` (Vault PKI CA) |
| `admin_root_cafile_path` | `/etc/forge/carbide-api/site/admin_root_cert_pem` | `deploy/files/carbide-api/admin_root_cert_pem` |

---

### 12b. Files that MUST be filled before production deploy

#### `helm-prereqs/values.yaml`

```yaml
siteName: "yoursite"       # replace TMP_SITE — injected into postgres pods

vault:
  nicoCliClientRole:
    enabled: true          # recommended: creates Vault PKI role for short-lived CLI certs
    name: "nico-cli-client"
    organization: "your-org"   # optional SubjectO in CLI client certs
```

#### `helm-prereqs/values/ncx-core.yaml`

Replace every `EXAMPLE` placeholder:

```yaml
carbide-api:
  hostname: "api-<SITE>.<DOMAIN>"    # external DNS name for carbide-api

  externalService:
    annotations:
      metallb.universe.tf/loadBalancerIPs: "<carbide-api VIP>"

  siteConfig:
    carbideApiSiteConfig: |
      sitename = "<SITE>"
      initial_domain_name = "<SITE>.<DOMAIN>"
      dhcp_servers = ["<DHCP VIP>"]
      site_fabric_prefixes = ["<tenant CIDR>"]
      deny_prefixes = ["<admin CIDR>", "<IPMI CIDRs>"]

      [pools.lo-ip]
      type = "ipv4"
      ranges = [{ start = "<start>", end = "<end>" }]

      [networks.admin]
      type = "admin"
      prefix = "<admin CIDR>"
      gateway = "<admin GW>"
      mtu = 9000
      reserve_first = 5

      [networks.<underlay-name>]   # one block per underlay L3 segment
      type = "underlay"
      prefix = "<underlay CIDR>"
      gateway = "<underlay GW>"
      mtu = 1500
      reserve_first = 5

carbide-dhcp:
  externalService:
    annotations:
      metallb.universe.tf/loadBalancerIPs: "<DHCP VIP>"

carbide-dns:
  externalService:
    perPodAnnotations:
      - metallb.universe.tf/loadBalancerIPs: "<DNS VIP 0>"
      - metallb.universe.tf/loadBalancerIPs: "<DNS VIP 1>"

carbide-pxe:
  externalService:
    annotations:
      metallb.universe.tf/loadBalancerIPs: "<PXE VIP>"

carbide-ssh-console-rs:
  externalService:
    annotations:
      metallb.universe.tf/loadBalancerIPs: "<SSH console VIP>"
```

#### `helm-prereqs/values/metallb-config.yaml`

```yaml
# Replace with real node hostnames (kubectl get nodes), ASNs, and TOR switch IPs.
BGPPeer[*].spec.myASN:     <cluster-side ASN, same for all nodes>
BGPPeer[*].spec.peerASN:   <TOR switch ASN, unique per node>
BGPPeer[*].spec.peerAddress: <TOR switch IP reachable from each node>
BGPPeer[*].spec.nodeSelectors: <actual node hostname>
IPAddressPool (internal): <CIDR for DHCP/PXE/DNS/SSH/NTP VIPs>
IPAddressPool (external): <CIDR for carbide-api VIP>
```

---

### 12c. `admin_root_cert_pem` — the out-of-band admin CA

This is the **only manual PKI step** not automated by `setup.sh`. It is intentionally
out-of-band: the admin CA private key must never be stored on-cluster.

**Step 1 — Generate the admin CA (on a secure workstation, keep the key offline):**

```bash
openssl ecparam -name prime256v1 -genkey -noout -out admin-ca.key
openssl req -new -x509 -key admin-ca.key -sha256 -days 3650 \
  -out admin-ca.crt \
  -subj "/CN=carbide-admin-ca/O=<your-org>"
```

**Step 2 — Place the CA cert into the deployment file:**

```bash
# deploy/files/carbide-api/admin_root_cert_pem
# Replace the placeholder with the real PEM:
cp admin-ca.crt deploy/files/carbide-api/admin_root_cert_pem
```

The file must be a valid PEM — it is loaded by `carbide-api` at TLS acceptor
construction time. If missing or unparseable, `carbide-api` logs a warning and
continues, but **all admin CLI connections will fail** (client cert CA not trusted).

**Step 3 — Issue an operator client cert from the admin CA:**

```bash
openssl ecparam -name prime256v1 -genkey -noout -out operator.key
openssl req -new -key operator.key -out operator.csr \
  -subj "/CN=<operator-name>/O=<your-org>"
openssl x509 -req -in operator.csr \
  -CA admin-ca.crt -CAkey admin-ca.key -CAcreateserial \
  -out operator.crt -days 365 -sha256
```

Distribute `operator.crt` + `operator.key` to each operator. Revoke by rotating
`admin_root_cert_pem` to a new CA and redeploying.

---

### 12d. Get the server-side CA for CLI → server verification

After `setup.sh` completes, the Vault PKI CA (derived from `site-root`) is available via:

```bash
# Export the forge-roots CA cert (used by the CLI to verify carbide-api's server cert)
kubectl get secret forge-roots -n forge-system \
  -o jsonpath='{.data.ca\.crt}' | base64 -d > site-root-ca.crt
```

This is what the CLI passes as `--forge-root-ca-path` (or `forge_root_ca_path` in
the config file) to verify the carbide-api TLS server certificate.

---

### 12e. Configure `carbide-admin-cli` on the operator workstation

The CLI resolves cert paths in this priority order (first match wins):

| What | Priority 1 | Priority 2 | Priority 3 | Auto-path |
|---|---|---|---|---|
| Server CA | `--forge-root-ca-path` | `FORGE_ROOT_CA_PATH` env | `~/.config/carbide_api_cli.json` | `/var/run/secrets/spiffe.io/ca.crt` → `/opt/forge/forge_root.pem` |
| Client cert | `--client-cert-path` | `CLIENT_CERT_PATH` env | `~/.config/carbide_api_cli.json` | `/var/run/secrets/spiffe.io/tls.crt` → `/opt/forge/machine_cert.pem` |
| Client key | `--client-key-path` | `CLIENT_KEY_PATH` env | `~/.config/carbide_api_cli.json` | `/var/run/secrets/spiffe.io/tls.key` → `/opt/forge/machine_cert.key` |
| API URL | `--carbide-api` / `-c` | `CARBIDE_API_URL` env | `~/.config/carbide_api_cli.json` | `https://carbide-api.forge-system.svc.cluster.local:1079` |

**Recommended: use a config file so you don't need flags every time:**

```json
// $HOME/.config/carbide_api_cli.json
{
  "carbide_api_url":   "https://api-<SITE>.<DOMAIN>:1079",
  "forge_root_ca_path": "/path/to/site-root-ca.crt",
  "client_cert_path":  "/path/to/operator.crt",
  "client_key_path":   "/path/to/operator.key"
}
```

- `forge_root_ca_path` → `site-root-ca.crt` from Step 12d (Vault PKI CA, verifies carbide-api server cert)
- `client_cert_path` + `client_key_path` → `operator.crt` / `operator.key` from Step 12c (admin-CA-signed, trusted by carbide-api via `admin_root_cert_pem`)

**Quick connectivity test:**

```bash
carbide-admin-cli version
# Expected: prints API server version (e.g. "v2025.x.x")
```

---

### 12f. Devspace (lab) vs production cert path comparison

| | Devspace (lab) | Production (`helm-prereqs`) |
|---|---|---|
| Root CA | `forge-local-ca` (self-signed, created by `bootstrap-prereqs.sh`) | `site-root` (self-signed, 10-year, created by `setup.sh`) |
| Service cert issuer | `Issuer/local-ca-issuer` (cert-manager CA issuer) | `ClusterIssuer/vault-forge-issuer` (Vault PKI backed by `site-root`) |
| `forge-roots` Secret | Populated by `sync_forge_roots_secret()` in `bootstrap-prereqs.sh` | Populated by ESO `ClusterExternalSecret/forge-roots-eso` |
| `admin_root_cert_pem` | Not set — `bypass_rbac = true` in `values.base.yaml` masks the missing admin CA | Must be set to a real admin CA PEM in `deploy/files/carbide-api/admin_root_cert_pem` |
| CLI server CA | `dev/certs/localhost/ca.crt` (auto-discovered via `$REPO_ROOT`) | `site-root-ca.crt` exported from `forge-roots` Secret |
| CLI client cert | `dev/certs/localhost/client.crt` (auto-discovered via `$REPO_ROOT`) | `operator.crt` signed by your admin CA |
| machine-a-tron | Commented out in `devspace.yaml` — no hardware simulation | Not applicable in production (real hardware via site-explorer) |
