# Day 0 / Day 1 / Day 2 Lifecycle

NICo organizes bare-metal lifecycle management into three phases: Day 0 (bringup), Day 1 (configuration), and Day 2 (operations).

## Day 0 — Discovery, Validation, and Ingestion

Day 0 covers everything from hardware arriving in the rack to a host being declared ready for tenant use. The design goal is zero-touch: once a host is racked and cabled, NICo handles discovery through provisioning-ready.

**Hardware discovery**
NICo discovers hardware via Redfish over the OOB (out-of-band) network. The site controller's crawler probes BMC endpoints, collects full hardware inventory (CPU, GPU, NIC, DPU, storage), and links each DPU to its host server via LLDP and serial number matching. No manual inventory entry is required.

**SKU validation and burn-in**
Before ingestion, NICo validates that each machine matches its expected SKU — flagging any missing or unexpected components. It then runs hardware and connectivity tests, including multi-node tests for systems participating in InfiniBand or NVLink fabrics.

**Firmware baseline**
NICo inventories UEFI and BMC firmware and updates any host that does not meet the site's baseline before making it available. Hosts that cannot be brought to baseline are quarantined automatically.

**DPU provisioning**
NICo installs the DPU OS, provisions HBN (Host-Based Networking with Containerized Cumulus), and configures all DPU firmware components (BMC, NIC, UEFI, ATF). The DPU agent starts after provisioning, periodically fetches desired configuration from NICo over gRPC, and reports applied state back.

**Attestation**
NICo attests each host via Measured Boot PCR checking and TPM signature verification before it enters the available pool.

**Network and IP setup**
IP address pools (BGP, loopback, host OS), DHCP, and DNS are allocated and configured automatically as part of the ingestion workflow.

---

## Day 1 — Isolation, Lockdown, and Provisioning

Day 1 covers the configuration of isolation boundaries and the provisioning of hosts for tenant use.

**Network isolation**
Before a host is assigned to a tenant, NICo establishes isolation across all applicable network planes:
- **Ethernet** — BlueField HBN enforces L3 VXLAN/EVPN boundaries and per-tenant VRFs. No leaf switch configuration changes are required.
- **InfiniBand** — UFM assigns P_Key partitions to the host's IB ports for the specific tenant.
- **NVLink** — NMX-M APIs configure NVLink partition assignments for the tenant's NVL domain.

**Host lockdown**
NICo applies UEFI lockdown (preventing unauthorized BIOS changes during tenant use), configures BMC security settings, and disables in-band host-to-BMC communications.

**OS provisioning**
NICo coordinates the PXE/iPXE boot sequence to install the tenant's chosen OS image. It sets UEFI boot order, applies security settings, and hands off to the caller once the host is booting. NICo does not manage what is installed beyond the boot handoff — OS configuration is the operator's or tenant's responsibility.

**Instance management**
Operators define instance types (hardware classes such as GPU node configurations) and allocate hosts to tenants as instances via the REST API or gRPC API. For GB200 NVL72 systems, allocations are NVL domain-batched to preserve NVLink topology integrity.

---

## Day 2 — Operations, Health, and Tenant Transitions

Day 2 covers the ongoing operation of active infrastructure and the lifecycle between tenant uses.

**Continuous monitoring**
NICo continuously monitors hardware health via Redfish polling and DPU agent telemetry. Metrics are exported in Prometheus format and can be consumed by operator monitoring stacks (Grafana, Loki, OpenTelemetry). Hardware events and health anomalies are surfaced via the NICo API and alerting integrations.

**Firmware updates**
NICo schedules UEFI and BMC firmware updates on healthy, unoccupied hosts — entirely out-of-band, without disrupting active tenants. Updates are applied against the site baseline and tracked in the per-machine firmware inventory.

**Tenant transitions (sanitization)**
When a tenant releases a host, NICo performs a full cleanup sequence before the host re-enters the available pool:
1. Secure erase of all NVMe storage
2. GPU memory and system memory wipe
3. TPM reset
4. Re-attestation via Measured Boot and TPM verification
5. Firmware integrity re-validation
6. Network isolation state cleared and re-provisioned for the next tenant

**Break-fix**
NICo supports directed provisioning for break-fix workflows: targeted machine provisioning to specific hosts, machine labels for tracking machines under repair, and issue reporting APIs for integration with service management tooling.

**Rack-scale health response (GB200)**
For GB200 NVL72 systems, NICo's rack-level management layer responds to health signals — leakage events, power anomalies, NVLink fabric degradation — with configurable, policy-based automated responses, including graceful workload shutdown, rack isolation, and recovery sequencing.
