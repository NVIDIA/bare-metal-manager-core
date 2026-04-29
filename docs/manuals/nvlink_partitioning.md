# NVLink Partitioning

NVIDIA [NVLink](https://www.nvidia.com/en-us/data-center/nvlink/) is a high-speed interconnect technology that allows for memory-sharing between GPUs. Sharing
is allowed between all GPUs in an *NVLink Partition*. An *NVLink Partition* must consist of GPUs within the same *NVLink Domain*, which can be a single NVL72 rack or two NVL36 racks cabled together.

NVIDIA Infra Controller (NICo) allows you to do the following with NVLink:

* Create, update, and delete NVLink Logical Partitions using the NICo REST API.
* Provision Instances with GPUs partitioned into NVLink Domains by way of NVLink Logical Partitions without knowledge of the underlying NVLink topology.
* Update Instances to change NVLink Logical Partition assignment for its GPUs

NICo extends the concept of an *NVLink Partition* with the *NVLink Logical Partition*, which allows users to manage NVLink Partitions without having to learn the datacenter topology.

> **Note**: NVLink Partitioning is only supported for GB200 compute nodes.

### Creating a NVLink Logical Partition

NICo users can create NVLink Logical Partitions and plan GPU assignments using NVLink Interfaces for Instances (as described in steps **1-2**). NICo can also automatically generate NVLink Interfaces and assign them to Instances (as described in step **3**).

In general, the steps are:

1. The user creates a NVLink Logical Partition using the `POST /v2/org/{org}/carbide/nvlink-logical-partition` [REST API endpoint](https://nvidia.github.io/infra-controller-rest/#tag/NVLink-Logical-Partition/operation/create-nvlink-logical-partition). NICo creates an entry in the database and returns an NVLink Logical Partition ID. At this point, there is no underlying NVLink Partition associated with the NVLink Logical Partition.

2. When creating an Instance, the user specifies NVLink Interface configuration for each GPU by referencing their preferred NVLink Logical Partition ID in the `POST /v2/org/{org}/carbide/instance` [REST API endpoint request](https://nvidia.github.io/infra-controller-rest/#tag/Instance/operation/create-instance).

   a. If this is the first Instance to be added to specified NVLink Logical Partitions, NICo Core will create and assign NVLink Partitions for them and add the Instance GPUs to the NVLink Partitions.

> **Note**: To ensure that machines in the same Rack are assigned to the same NVLink Partition, an Instance Type can be created for the Rack and all Machines in the Rack assigned to the same Instance Type. Alternatively users can use the [Batch Instance creation REST API endpoint](https://nvidia.github.io/infra-controller-rest/#tag/Instance/operation/batch-create-instances) and set `topologyOptimized` to `true`.

3. If the user does not want to specify NVLink Interfaces for each GPU when creating an Instance, they can:

   a. Create a new VPC by specifying a value for `nvLinkLogicalPartitionId` or update an existing VPC with no Instances to set the `nvLinkLogicalPartitionId` attribute. We will refer to this as the *default NVLink Logical Partition* for the VPC.

   b. When creating an Instance in this VPC, user does not need to specify NVLink Interfaces, NICo will automatically generate NVLink Interfaces for the Instance and assign them to the VPC's NVLink Logical Partition.

   c. All Instances created within this VPC will have their GPUs assigned to the same NVLink Partition as long as the Instances end up in the same Rack.

   d. If there is no space in the Rack where the NVLink Partition for an NVLink Logical Partition is located, NICo will create a new NVLink Partition in a different Rack for the same NVLink Logical Partition and continue to assign the Instance GPUs to it.

> **Important**: If Instances are in different Racks, they will not be able to share memory with each other despite having the same NVLink Logical Partition.

### Updating an Instance to change NVLink Logical Partition assignment for its GPUs

If a NICo user wants to update an Instance to change NVLink Logical Partition assignment for its GPUs, they can do so by calling the `PATCH /v2/org/{org}/carbide/instance/{instance-id}` [REST API endpoint](https://nvidia.github.io/infra-controller-rest/#tag/Instance/operation/update-instance)

The user can specify the NVLink Logical Partition ID for each GPU in the Instance by passing the `nvLinkInterfaces` list.

If Instance's VPC has a default NVLink Logical Partition, no changes to the NVLink Logical Partition assignment are allowed.

### Removing Instances from a Logical Partition

If a user de-provisions an Instance, NICo will remove the Instance GPUs from the NVLink Partition.

### Deleting an NVLink Logical Partition

A NICo user can call `DELETE /v2/org/{org}/carbide/nvlink-logical-partition/{nvLinkLogicalPartitionId}` to delete an NVLink Logical Partition. This call will only succeed if there are no active Instances associated with the NVLink Logical Partition.

### Retrieving NVLink Partition Information for an Instance

A NICo user can call `GET /v2/org/{org}/carbide/instance/{instance-id}` to retrieve information about an Instance. As part of the `200` response body, NICo will return a `nvLinkInterfaces` list that includes both the `nvLinkLogicalPartitionId` and `nvLinkDomainId` for each GPU in the Instance.

### Default NVLink Logical Partition for a VPC

**It's an optional default, not a constraint.**
VPCs can be created with or without a default NVLink Logical Partition.

It is optional on both `POST .../vpc` (Create VPC) and `PATCH .../vpc/{vpcId}` (Update VPC).

**What setting it on a VPC actually does**
It's a convenience default for instance creation. When `nvLinkLogicalPartitionId` is set on the VPC, you don't have to specify `nvLinkInterfaces` on `POST .../instance` (Create Instance) or `POST .../instance/batch` (Batch Create Instances) — the API will auto-populate the per-GPU NVLink Interfaces to reference that VPC's NVLink Logical Partition.
That's the entire effect. It does not reserve or lock the NVLink Logical Partition to the VPC.

**No exclusivity between VPCs**
We intentionally don't restrict an NVLink Logical Partition to a single VPC. The same `nvLinkLogicalPartitionId` may be set on multiple VPCs. This is deliberate, to preserve flexibility in how you plan networking and NVLink partitioning.

**You can also manage NVLink at the Instance level**
If you want finer control, leave `nvLinkLogicalPartitionId` unset on the VPC and specify `nvLinkInterfaces` directly on Create Instance — each entry binds a specific `deviceInstance` (GPU) to an explicit `nvLinkLogicalPartitionId`, so different GPUs in the same instance (or across Instances in the same VPC) can operate in different NVLink Logical Partitions.

**Summary**
| Configuration | Behavior |
| --- | --- |
| VPC has `nvLinkLogicalPartitionId`, Instance creation omits `nvLinkInterfaces` | API auto-populates all GPUs to the VPC's NVLink Logical Partition |
| VPC has `nvLinkLogicalPartitionId`, Instance specifies `nvLinkInterfaces` | Instance-level values must align with VPC's Partition, rendering the specification redundant |
| VPC doesn't have `nvLinkLogicalPartitionId` set, Instance specifies `nvLinkInterfaces` | Per-GPU NVLink Logical Partition assignments are used |
| Same `nvLinkLogicalPartitionId` on multiple VPCs | Allowed — no implicit exclusivity |
