# NVIDIA Metal

NVIDIA Metal exists to manage the end-to-end lifecycle of bare-metal machines consisting of NVIDIA certified hardware and software, as well as managing allocation of this bare metal to external organizations and customers.  It is designed to support network virtualization, and enable fungible capacity in a purely automatic way.   NVIDIA Metal is intended to be multi-datacenter, multi-tenant, with a single cloud-control plane for management of sites and hardware within those sites.  NVIDIA Metal is a "Bare Metal as-a-service" offering built on NVIDIA Hardware and Software.

NVIDIA Metal has two major components.  First, a cloud control plane that can manage multiple sites, handles account management, billing and scheduling of hardware and instances to various tenants.  Next is the on-prem control plane that manages the end-to-end lifecycle of individual machines and networks between those machines.

This set of documentation covers only the technical documentation for the on-premesis NVIDIA Metal control plane.  It does not cover the NVIDIA Metal cloud control plane.

NVIDIA Metal's responsibility ends at booting the machine into a user-defined Host OS, all further responsibilty is outside the scope of NVIDIA Metal.

```mermaid
flowchart LR

    subgraph Legend
        legend_untrusted(Untrusted)
        legend_trusted(Trusted)
    end

    subgraph cloud["NVIDIA Metal Cloud"]
        kafka[(Kafka Server Instance)]
    end
    subgraph NVIDIA Metal Region
        region(("Control Plane"))
        subgraph Tenant Capacity
            machine-1:::untrusted
            machine-2:::untrusted
            machine-3:::untrusted
            machine-N:::untrusted
        end
    end

    region ===>|Kafka| kafka
    region -..-> machine-1
    region -..-> machine-2
    region -..-> machine-3
    region -..-> machine-N

    classDef nvidia fill:#76b900,stroke:#333,stroke-width:4px;
    classDef untrusted fill:#c0211d,stroke:#900d09,stroke-width:4px,stroke-dasharray: 5 5;

    class legend_untrusted untrusted
    class legend_trusted,region,cloud nvidia
```

## NVIDIA Metal principles

* The machine is untrustworthy
* We cannot impose any requirements on operating system running on the machine
* After being racked, machines must become ready for tenant use with no human intervention
* The machine must be able to assert trustworthiness at any time or be removed from the pool
* All monitoring of the machine must be done via out-of-band methods
* End-to-end SLO is inclusive of planned and unplanned maintenance
* Keep the underlay and fabric configuration as static and simple as possible

## NVIDIA Metal responsibilities

* Maintain Hardware Inventory
* Perform initial IPMI setup of usernames/password
* Hardware Testing & Burn-in
* Firmware validation & updating
* IP address allocation (IPv4 & IPv6)
* Power control (power on/off/reset)
* Provide DNS services for managed machines
* Orchestrating provisioning, wiping, & releasing nodes
* Ensuring trust of the machine when switching tenants

## NVIDIA Metal Non-goals

* Configuration of services & software running on managed machines
* Cluster assembly (i.e. it does not build SLURM or Kubernetes clusters)
* Underlay network management
