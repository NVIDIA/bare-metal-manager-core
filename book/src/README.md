# Overview

NCX Infra Controller (NICo) is an API-based microservice that provides site-local, zero-trust bare-metal lifecycle management with DPU-enforced isolation, allowing for deployment of multi-tenant AI infrastructure at scale. NICo enables zero-touch automation and ensures the integrity and separation of workloads at the bare-metal layer.

## NICo Operational Principles

NICo has been designed according to the following principles:

* The machine is untrustworthy.
* Operating system requirements are not imposed on the machine.
* After being racked, machines must become ready for use with no human intervention.
* All monitoring of the machine must be done using out-of-band methods.
* The network fabric (i.e. Leaf Switches and routers) stays static even during tenancy changes within NICo.

## NICo Responsibilities

NICo is responsible for the following tasks in the data-center environment:

* Maintain hardware inventory of ingested machines.
* Integrate with RedFish APIs to manage usernames and passwords
* Perform hardware testing and burn-in.
* Validate and update firmware.
* Allocate IP addresses (IPv4).
* Control power (power on/off/reset).
* Provide DNS services for managed machines.
* Orchestrate provisioning, wiping, and releasing nodes.
* Ensure trust of the machine when switching tenants.

### Responsibilities not Covered

NICo is not responsible for the following tasks:

* Configuration of services and software running on managed machines.
* Cluster assembly (that is, it does not build SLURM or Kubernetes clusters)
* Underlay network management

## NICo Components and Services

NICo is a service with multiple components that drive actions based on API calls, which can originate from users or
as events triggered by machines (e.g. a DHCP boot or PXE request).

Each service communicates with the NICo API server over [gRPC](https://grpc.io) using
[protocol buffers](https://developers.google.com/protocol-buffers). The API uses
[gRPC reflection](https://github.com/grpc/grpc/blob/master/doc/server-reflection.md) to provide a machine readable API
description so clients can auto-generate code and RPC functions in the client.

The NICo deployment includes a number of services:

- **NICo API service**: Allows users to query the state of all objects and to request creation, configuration, and deletion of entities using a REST API.
- **DHCP**: Provides IPs to all
  devices on underlay networks, including Host BMCs, DPU BMCs, and DPU OOB addresses. It also
  provides IPs to Hosts on the overlay network.
- **PXE**: Delivers images to
  managed hosts at boot time. Currently, managed hosts are configured to always boot from PXE. If a local
  bootable device is found, the host will boot it. Hosts can also be configured to always boot from a
  particular image for stateless configurations.
- **Hardware health**: Pulls
  hardware health and configuration information emitted from a Prometheus `/metrics` endpoint on port 9009 and
  reports that state information back to NICo.
- **SSH console**: Provides a virtual serial
  console logging and access over `ssh`, allowing console access to remote machines deployed on site.
  The `ssh-console` also logs the serial console output of each host into the logging system, where
  it can be queried using tools such as Grafana and `logcli`.
- **DNS**: Provides domain name service (DNS) functionality
  using two services:
  - `carbide-dns`: Handles DNS queries from the site controller and managed nodes.
  - `unbound`: Provides recursive DNS services to managed machines and instances.

### Component and Service Dependencies

In addition to the NICo service components, there are other supporting services that must be set up within the K8s site
controller nodes.

#### Site Management

- The entry point for the managed site is through the Elektra site agent.
  The site agent maintains a northbound Temporal connection to the cloud control plane for command and control.
- The admin CLI provides a command line interface into NICo.

> **Note**: The REST API is the primary way to interact with NICo and should be used for all state-modifying operations (creating/modifying tenants, VPCs, instances, etc). The admin CLI is a convenience tool for administrative tasks and should not be relied upon for production workflows.

#### Kubernetes

Some site controller node services require persistent, durable storage to maintain state for their attendant
pods:

- [Hashicorp Vault](https://www.vaultproject.io/): Used by Kubernetes for certificate signing requests (CSRs), this vault
  uses three each (one per K8s control node) of the `data-vault` and `audit-vault` 10GB PVs to protect and distribute
  the data in the absence of a shared storage solution.
- [Postgres](https://www.postgresql.org/): This database is used to store state for any NICo or site controller
  components that require it, including the main "forgedb". There are three 10GB `pgdata` PVs deployed to protect
  and distribute the data in the absence of a shared storage solution. The `forgedb` database is stored here.
- Certificate Management Infrastructure: This is a set of components that manage the certificates for the site controller and managed hosts.

### Managed Hosts

The point of having a site controller is to administer a site that has been populated with managed hosts.
Each managed host is a pairing of a single Bluefield (BF) 2/3 DPU and a host server.
During initial deployment, the `scout` service runs, informing the NICo API of any discovered DPUs. NICo completes the installation of services on the DPU and boots into regular operation mode. Thereafter, the `dpu-agent` starts as a daemon.

Each DPU runs the `dpu-agent` which connects via gRPC to the API service in NICo to get configuration
instructions.

### Metrics and Logs

NICo collects metrics and logs from the managed hosts and the site controller. This information is in Prometheus format and can be scraped by a Prometheus server.