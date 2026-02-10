# NVIDIA Bare Metal Manager

NVIDIA Bare Metal Manager exists to manage the end-to-end lifecycle of bare-metal machines consisting of NVIDIA certified hardware and software, as well as managing allocation of this bare metal to external organizations and customers.  It is designed to support network virtualization, and enable fungible capacity in a purely automatic way.  NVIDIA Bare Metal Manager is a "Bare Metal as-a-service" offering built on NVIDIA Hardware and Software.

NVIDIA Bare Metal Manager's responsibility ends at booting the machine into a user-defined Host OS, all further responsibility is outside the scope of NVIDIA Bare Metal Manager.

## NVIDIA Bare Metal Manager principles

* The machine is untrustworthy
* We cannot impose any requirements on operating system running on the machine
* After being racked, machines must become ready for tenant use with no human intervention
* All monitoring of the machine must be done via out-of-band methods
* Keep the underlay and fabric configuration as static and simple as possible

## NVIDIA Bare Metal Manager responsibilities

* Maintain Hardware Inventory
* Perform initial Redfish setup of usernames/password
* Hardware Testing & Burn-in
* Firmware validation & updating
* IP address allocation (IPv4)
* Power control (power on/off/reset)
* Provide DNS services for managed machines
* Orchestrating provisioning, wiping, & releasing nodes
* Ensuring trust of the machine when switching tenants

## NVIDIA Bare Metal Manager Non-goals

* Configuration of services & software running on managed machines
* Cluster management (i.e. it does not build SLURM or Kubernetes clusters)
* Underlay network management
