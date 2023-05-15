[View SVG](schema.svg)

```mermaid
erDiagram
    sqlx_migrations {
        bigint version PK
        text description
        timestamp_with_time_zone installed_on
        boolean success
        bytea checksum
        bigint execution_time
    }

    instance_types {
        uuid id PK
        character_varying short_name
        text description
        instance_type_capabilities capabilities
        boolean active
        timestamp_with_time_zone created
        timestamp_with_time_zone updated
    }

    vpc_resource_leafs {
        character_varying id PK
        inet loopback_ip_address
    }

    machine_topologies {
        character_varying machine_id PK
        jsonb topology
        timestamp_with_time_zone created
        timestamp_with_time_zone updated
    }

    instances {
        uuid id PK
        character_varying machine_id FK
        timestamp_with_time_zone requested
        timestamp_with_time_zone started
        timestamp_with_time_zone finished
        text user_data
        text custom_ipxe
        ARRAY ssh_keys
        boolean use_custom_pxe_on_boot
        character_varying network_config_version
        jsonb network_config
        jsonb network_status_observation
        text tenant_org
        timestamp_with_time_zone deleted
    }

    machines {
        character_varying id PK
        character_varying vpc_leaf_id FK
        uuid supported_instance_type FK
        timestamp_with_time_zone created
        timestamp_with_time_zone updated
        timestamp_with_time_zone deployed
        character_varying controller_state_version
        jsonb controller_state
        timestamp_with_time_zone last_reboot_time
        timestamp_with_time_zone last_cleanup_time
        timestamp_with_time_zone last_discovery_time
        jsonb network_status_observation
        character_varying network_config_version
        jsonb network_config
    }

    domains {
        uuid id PK
        character_varying name
        timestamp_with_time_zone created
        timestamp_with_time_zone updated
        timestamp_with_time_zone deleted
    }

    vpcs {
        uuid id PK
        character_varying name
        character_varying organization_id
        character_varying version
        timestamp_with_time_zone created
        timestamp_with_time_zone updated
        timestamp_with_time_zone deleted
    }

    network_prefixes {
        uuid id PK
        uuid segment_id FK
        cidr prefix
        inet gateway
        integer num_reserved
        text circuit_id
    }

    network_segments {
        uuid id PK
        character_varying name
        uuid subdomain_id FK
        uuid vpc_id FK
        integer mtu
        character_varying version
        timestamp_with_time_zone created
        timestamp_with_time_zone updated
        timestamp_with_time_zone deleted
        integer vni_id
        character_varying controller_state_version
        jsonb controller_state
        smallint vlan_id
        network_segment_type_t network_segment_type
    }

    machine_interface_addresses {
        uuid id PK
        uuid interface_id FK
        inet address
    }

    tags {
        uuid id PK
        character_varying slug
        character_varying name
    }

    tags_networksegment {
        uuid tag_id FK
        uuid target_id FK
    }

    machine_interfaces {
        uuid id PK
        character_varying attached_dpu_machine_id FK
        character_varying machine_id FK
        uuid segment_id FK
        macaddr mac_address
        uuid domain_id FK
        boolean primary_interface
        character_varying hostname
    }

    dhcp_entries {
        uuid machine_interface_id PK
        character_varying vendor_string PK
    }

    tags_machine {
        uuid tag_id FK
        character_varying target_id FK
    }

    ssh_public_keys {
        character_varying username
        user_roles role
        ARRAY pubkeys
    }

    machine_state_controller_lock {
        uuid id
    }

    mq_msgs {
        uuid id PK
        timestamp_with_time_zone created_at
        timestamp_with_time_zone attempt_at
        integer attempts
        interval retry_backoff
        text channel_name
        text channel_args
        interval commit_interval
        uuid after_message_id FK
    }

    mq_payloads {
        uuid id PK
        text name
        jsonb payload_json
        bytea payload_bytes
    }

    bg_status {
        uuid id PK
        jsonb status
        timestamp_with_time_zone last_updated
    }

    instance_addresses {
        uuid id
        uuid instance_id FK
        text circuit_id
        inet address
    }

    network_segments_controller_lock {
        uuid id
    }

    network_segment_state_history {
        bigint id PK
        uuid segment_id
        jsonb state
        character_varying state_version
        timestamp_with_time_zone timestamp
    }

    machine_state_history {
        bigint id PK
        character_varying machine_id
        jsonb state
        character_varying state_version
        timestamp_with_time_zone timestamp
    }

    machine_console_metadata {
        character_varying machine_id FK
        character_varying username
        user_roles role
        character_varying password
        console_type bmctype
    }

    resource_pool {
        bigint id PK
        character_varying name
        character_varying value
        timestamp_with_time_zone created
        timestamp_with_time_zone allocated
        jsonb state
        character_varying state_version
    }

    tenants {
        text organization_id PK
        character_varying version
    }

    tenant_keysets {
        text organization_id PK
        text keyset_id PK
        jsonb content
        character_varying version
    }

    ibsubnet_controller_lock {
        uuid id
    }

    ib_subnets {
        uuid id PK
        character_varying name
        uuid vpc_id FK
        character_varying config_version
        jsonb status
        timestamp_with_time_zone created
        timestamp_with_time_zone updated
        timestamp_with_time_zone deleted
        character_varying controller_state_version
        jsonb controller_state
    }

    machines }o--|| instance_types : "supported_instance_type"
    machines }o--|| vpc_resource_leafs : "vpc_leaf_id"
    machine_topologies |o--|| machines : "machine_id"
    instance_addresses }o--|| instances : "instance_id"
    instances }o--|| machines : "machine_id"
    machine_interfaces }o--|| machines : "attached_dpu_machine_id"
    tags_machine }o--|| machines : "target_id"
    machine_console_metadata }o--|| machines : "machine_id"
    machine_interfaces }o--|| machines : "machine_id"
    machine_interfaces }o--|| domains : "domain_id"
    network_segments }o--|| domains : "subdomain_id"
    network_segments }o--|| vpcs : "vpc_id"
    ib_subnets }o--|| vpcs : "vpc_id"
    network_prefixes }o--|| network_segments : "segment_id"
    machine_interfaces }o--|| network_segments : "segment_id"
    tags_networksegment }o--|| network_segments : "target_id"
    machine_interface_addresses }o--|| machine_interfaces : "interface_id"
    tags_networksegment }o--|| tags : "tag_id"
    tags_machine }o--|| tags : "tag_id"
    dhcp_entries }o--|| machine_interfaces : "machine_interface_id"
    mq_msgs }o--|| mq_msgs : "after_message_id"
```
