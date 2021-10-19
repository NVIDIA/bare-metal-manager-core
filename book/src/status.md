# Roadmap

This documentation is automatically compiled and deployed during CI/CD.

The authoritative source of project planning and work is [JIRA-SW](https://jirasw.nvidia.com/projects/NSVIS) in the "Base Command Metal" component in the [NSVIS Project](https://jirasw.nvidia.com/browse/NSVIS).

Following is a list of key milestones for development as of 19-Oct-2021.

## Phase 0 

- ✅ Initial database model / migration support
- ✅ Integration tests to create networks
- ✅ Integration tests to create machines
- ✅ Integration tests to assign IPs to machines on networks
- ✅ Generate a static PXE template for a known VM
- ❌ Assign an IP address to a previously unknown VM triggered by a DHCP request
- ❌ Deploy an operating system to a VM with simulated power on/power off
- ❌ Deploy an operating system to a machine by using IPMI to power on/off the machine and set boot order
- ❌ Build an ephemeral image used to run carbide components
- ❌ Implement machine discovery of hardware components
- ❌ Support UEFI boot for http booting
- ❌ Respond to DNS A and AAAA records for machines that exist in the database
- ❌ End to end rack deployment and re-deployment
- ❌ Integrate CI with re-deployment of racks

Phase 0 completion is when this software can deploy a real machine from previously unknown state to deployed OS

## Phase 1

- ❌ Cloud-init support for customization of the booting operating system
- ❌ Implement (ABAC)[https://en.wikipedia.org/wiki/Attribute-based_access_control] policies on machine modification / actions
- ❌ Implement Firmware update framework
- ❌ Support moving a machine to a new network using Hydrazine

Phase 1 completion is when Carbide can control and deploy machines in a multi-tenant environment

## Phase 2

- ❌ Support hardware burn-in testing
- ❌ Support IPv6 deployment of machines
