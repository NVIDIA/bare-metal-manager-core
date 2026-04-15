# VPC Peering Management

VPC peering allows you to connect two VPCs together, enabling bi-directional network communication between instances in different VPCs. The peering relationship is treated as an unordered pair, so a peering between "vpc1" and "vpc2" is equivalent to a peering between "vpc2" and "vpc1".

This page explains how to manage VPC peering connections using either the REST API or the `carbide-admin-cli`.

## REST API Commands

The `/v2/org/{org}/carbide/vpc-peering` endpoint provides the following operations to manage VPC peerings:

- [POST /v2/org/{org}/carbide/vpc-peering](https://nvidia.github.io/ncx-infra-controller-rest/#tag/VPC-Peering/operation/create-vpc-peering): Create a new VPC peering connection between two VPCs
- [GET /v2/org/{org}/carbide/vpc-peering](https://nvidia.github.io/ncx-infra-controller-rest/#tag/VPC-Peering/operation/get-all-vpc-peering): List all VPC peering connections
- [GET /v2/org/{org}/carbide/vpc-peering/{id}](https://nvidia.github.io/ncx-infra-controller-rest/#tag/VPC-Peering/operation/get-vpc-peering): Get a VPC peering connection by ID
- [DELETE /v2/org/{org}/carbide/vpc-peering/{id}](https://nvidia.github.io/ncx-infra-controller-rest/#tag/VPC-Peering/operation/delete-vpc-peering): Delete a VPC peering connection

### Create a new VPC Peering Connection

[POST /v2/org/{org}/carbide/vpc-peering](https://nvidia.github.io/ncx-infra-controller-rest/#tag/VPC-Peering/operation/create-vpc-peering)

```bash
curl -X POST https://carbide-rest-api.carbide.svc.cluster.local/v2/org/org/carbide/vpc-peering \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
  "vpc1Id": "497f6eca-6276-4993-bfeb-53cbbbba6f08",
  "vpc2Id": "34f5c98e-f430-457b-a812-92637d0c6fd0",
  "siteId": "72771e6a-6f5e-4de4-a5b9-1266c4197811"
}'
```

The following must be true for the VPC peering creation request to be successful:

- The site must exist and be in Registered state.
- `vpc1Id` and `vpc2Id` must be different.
- Both VPCs must exist.
- Both VPCs must belong to the specified site of `siteId`.
- Both VPCs must be in Ready state.
- Duplicate peerings must be rejected, where duplicate means the same unordered VPC pair already exists.  

### Get All VPC Peering Connections

[GET /v2/org/{org}/carbide/vpc-peering](https://nvidia.github.io/ncx-infra-controller-rest/#tag/VPC-Peering/operation/get-all-vpc-peering)

```bash
curl https://carbide-rest-api.carbide.svc.cluster.local/v2/org/org/carbide/vpc-peering \
     -H "Authorization: Bearer <token>"
```

The following must be true for the VPC peering retrieval request to be successful:

- Pagination parameters must valid, with defaults and bounds applied as needed.

### Get a VPC Peering Connection by ID

[GET /v2/org/{org}/carbide/vpc-peering/{id}](https://nvidia.github.io/ncx-infra-controller-rest/#tag/VPC-Peering/operation/get-vpc-peering)

```bash
curl https://carbide-rest-api.carbide.svc.cluster.local/v2/org/org/carbide/vpc-peering/id \
     -H "Authorization: Bearer <token>"
```

The following must be true for the VPC peering retrieval request to be successful:

- The peering ID must be valid and parseable.
- The peering must exist.

### Delete a VPC Peering Connection

[DELETE /v2/org/{org}/carbide/vpc-peering/{id}](https://nvidia.github.io/ncx-infra-controller-rest/#tag/VPC-Peering/operation/delete-vpc-peering)

```bash
curl -X DELETE https://carbide-rest-api.carbide.svc.cluster.local/v2/org/org/carbide/vpc-peering/id \
     -H "Authorization: Bearer <token>"
```

The following must be true for the VPC peering deletion request to be successful:

- The peering ID must be valid and parseable.
- Both VPCs must be retrievable. The API determines whether the peering is multi-tenant by comparing the two VPC tenant IDs

## Admin CLI Commands

The `carbide-admin-cli vpc-peering` command provides three main operations:

```bash
carbide-admin-cli vpc-peering <COMMAND>

Commands:
  create  Create VPC peering connection
  show    Show list of VPC peering connections
  delete  Delete VPC peering connection
```

### Creating VPC Peering Connections

To create a new VPC peering connection between two VPCs:

```bash
carbide-admin-cli vpc-peering create <VPC1_ID> <VPC2_ID>
```

**Example:**
```bash
carbide-admin-cli vpc-peering create e65a9d69-39d2-4872-a53e-e5cb87c84e75 366de82e-1113-40dd-830a-a15711d54ef1
```

**Notes:**
- The operator should confirm with both VPC owners (VPC tenant org) that they approve the peering before creating the connection
- The VPC IDs can be provided in any order
- The system will automatically enforce canonical ordering (smaller ID becomes `vpc1_id`)
- If a peering connection already exists between the two VPCs, the command will return error indicating a peering connection already exists
- Both VPCs must exist before creating the peering connection

### Listing VPC Peering Connections

To view VPC peering connections, you can either show all connections or filter by a specific VPC:

**Show all peering connections:**
```bash
carbide-admin-cli vpc-peering show
```

**Show peering connections for a specific VPC:**
```bash
carbide-admin-cli vpc-peering show --vpc-id <VPC_ID>
```

**Example:**
```bash
# Show all peering connections
carbide-admin-cli vpc-peering show

# Show peering connections for a specific VPC
carbide-admin-cli vpc-peering show --vpc-id 550e8400-e29b-41d4-a716-446655440000
```

The output will display:
- Peering connection ID
- VPC1 ID (smaller UUID)
- VPC2 ID (larger UUID)
- Connection status
- Creation timestamp

### Deleting VPC Peering Connections

To delete an existing VPC peering connection:

```bash
carbide-admin-cli vpc-peering delete <PEERING_CONNECTION_ID>
```

**Example:**
```bash
carbide-admin-cli vpc-peering delete 123e4567-e89b-12d3-a456-426614174000
```

**Notes:**
- You need the peering connection ID (not the VPC IDs) to delete a connection
- Use the `show` command to find the peering connection ID
