# NVLink Partitioning

NVIDIA [NVLink](https://www.nvidia.com/en-us/data-center/nvlink/) is a high-speed interconnect technology that allows for memory-sharing between GPUs. Sharing
is allowed between all GPUs in an NVLink *partition*, and a *partition* is made up of GPUs within the same NVLink *domain*, which can be a single NVL72 rack or two NVL36 racks cabled together.

NVIDIA Bare Metal Manager (BMM) allows you to do the following with NVLink:

* Create, update, and delete NVLink partitions using the BMM API.
* Allocate instances to NVLink domains without knowledge of the underlying NVLink topology.
* Monitor NVLink partition status using telemetry.

BMM extends the concept of an *NVLink partition* with the *logical partition* structure, which allows users to manage NVLink partitions without knowing the datacenter topology. BMM users interact
with *logical partitions* through the instance creation process, as described in the following sections.

> **Note**: The following steps only apply to creating instances for GB200 compute nodes.

### Creating a Logical Partition

BMM users can create logical partitions and manually assign instances to them (as described in steps **1-2**). BMM can also automatically generate logical partitions and assign instances to them (as described in step **3**).

1. The user creates a logical partition using the `POST /v2/org/{org}/bmm/nvlink-logical-partition` call. BMM creates an entry in the database and returns a logical partition ID. At this point, there is no underlying NVLink partition associated with the logical partition.

2. When creating an instance, the user can specify a logical partition for the instance by passing the logical partition ID with the `POST /v2/org/{org}/carbide/instance` call.

   a. If this is the first instance to be added to the logical partition, BMM will create a new NVLink partition and add the instance GPUs to it.

> **Note**: To ensure that machines in the same rack are assigned to the same partition, create one instance type per rack.

3. If the users does not specify a logical partition when creating an instance, BMM will perform the following steps:

   a. BMM automatically generates a logical partition with the name `<vpc-name>-default`.

   b. BMM creates a new NVLink partition and adds the instance GPUs to it.

   c. When the user creates additional instances within the same VPC, BMM will add the instance GPUs to the same logical partition, as well as the same NVLink partition if there is space in the rack.

   d. If there is no space in the rack, BMM will create a new NVLink partition within the same logical partition and add the instance GPUs to it.

> **Important**: When BMM creates a new NVLink partition within the same logical partition, the new instance GPUs in the logical partition will not be able to share memory with the other instances that were previously added to the logical partition.

### Removing Instances from a Logical Partition

If a BMM user de-provisions an instance, BMM will remove the instance GPUs from the logical partition.

### Deleting a Logical Partition

A BMM user can call `DELETE /v2/org/{org}/bmm/nvlink-logical-partition/{nvLinkLogicalPartitionId}` to delete a logical partition. This call will only succeed if there are no physical partitions associated with the logical partition.

### Retrieving Partition Information for an Instance

A BMM user can call `GET /v2/org/{org}/bmm/instance/{instance-id}` to retrieve information about an instance. As part of the `200` response body, BMM will return a `nvLinkInterfaces` list that includes both the `nvLinkLogicalPartitionId` and `nvLinkDomainId` for each GPU in the instance.

The `nvLinkDomainId` can be useful in some use cases. For example, when BMM is being used to provide Virtual Machines as a Service (VMaaS), instances are created up front with no NVLink partition configured yet. Then, when a user spins up a virtual machine (VM), VMaaS schedules it on one of these instances. Once the user has a group of VMs, they configure an NVLink partition. However, the instances selected by VMaaS may all be in different NVLink domains, and won't be able to be added to a single partition. The NVLink domain IDs can be used by the VMaaS to make an informed decision regarding where to schedule the VMs.