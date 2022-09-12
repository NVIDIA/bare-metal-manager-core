# Forge Site Controller WorkFlow

## DPU Provisioning

![DPU provision](static/dpu_provision.png)

**Summary**

After this step, DPU is discovered by forge, HBN on DPU is configured by forge. 

- DPU ipxe boots
- DPU gets IP address from provisioner/kea, the IP will be on pre-allocatedIPMI network segment.
- DPU loads bfb image from provisioner/PXE server
- DPU runs cloud-init to install HBN etc, and inform provisioner DPU discovery info.
- Provisioner announces DPU presence as new leaf CRD to vpc.
- Vpc configures HBN to establish DPU data network connectivity.

## Host Provisioning

![Host provision](static/host_provision.drawio.png)

**Summary**

After this step, a x86 host is discovered by forge. The x86 host is imaged, and is connected to the network. The x86 host NICs and DPU port connectivities are discovered, and are updated to vpc.
Provisioner announces DPU ports (learnt through DPU discovery) to vpc.
Vpc enables dhcp relay on DPU.
- x86 ipxe boots
- x86 host gets IP from provisioner/KEA, the IP will be on the pre-allocated host admin network segment.
Provisioner announces x86 host IP to vpc.
- Vpc programs DPU to advertise the x86 host IP, now x86 host can access the network
- x86 host boots with a default image, and runs some cloud-init to inform the provisioner with discovery info.
- Provisioner correlates DPU and x86 host MachineDiscoveryInfo, and maps x86 NICs with connecting DPU ports, updates to vpc.

## Tenant Provisioning

![Tenant provision](static/tenant_provision.drawio.png)

**Summary**

After this step, a x86 host is assigned to a tenant, with tenant specified image, and overlay network.
Cloud control plane creates “VPC” and network segment to provisioner

- Provisioner announces the tenant network segment as ResourceGroup (including network info) CRD to vpc.
- Cloud control plane create Instance with associated network segments and image, etc,
- Provisioner announces the Instance as mangedResource (that associate an x86 host with the above network segment) to vpc
- Vpc configures DPU to place the x86 host on the overlay network
- Provisioner triggers x86 host to reboot
- X86 host pxe boots, Repeat DHCP and host boot steps in host provisioning steps
- X86 host boots with tenant image, and runs cloud-init script to inform provisioner with discovery instance info.

## Tenant De-provisioning

![Tenant deprovision](static/tenant_deprovision.drawio.png)

**Summary**

The tenant de-provisioning is ordered and asynchronous processes.
* Ordered: a network subnet cannot be deleted unless there are no instances associated with it; similarly a “VPC” cannot be deleted unless there are no subnets associated with it.
* Asynchronous: cloud control plane does not need to know or wait for x86 hosts to complete their de-provisioning and are put back to the un-assigned state.

## QueryAPIs
APIs that cloud agent would need in order to query machine and instance state and availability.

FindMachine (incomplete): Find machine based on
- Type: CPU/DPU
- Availability: Connected/Error
- Assignment status: assigned to tenant or not

FindInstance(Missing): Current state of an instance
- OS
- Network
- State
