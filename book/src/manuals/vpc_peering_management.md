# VPC Peering Management

VPC peering allows you to connect two VPCs together, enabling bi-directional network communication between instances in different VPCs. This page explains how to manage VPC peering connections using `carbide-admin-cli`.

## VPC Peering Commands

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
