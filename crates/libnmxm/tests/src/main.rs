use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // talk to prism mock server statndard endpoint
    let endpoint = libnmxm::Endpoint {
        host: "http://127.0.0.1:4010".to_string(),
        username: None,
        password: None,
    };

    let pool = libnmxm::NmxmClientPool::builder(true).build()?;
    let nmxm = pool.create_client(endpoint).await?;

    let mut json;

    let c = nmxm.get_chassis("".to_string()).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm.get_chassis_count(None).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm.get_gpu_count(None).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm.get_gpu(None).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm
        .get_partition("551137c2f9e1fac808a5f572".to_string())
        .await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm.get_partitions_list().await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm.get_switch_nodes_count(None).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm.get_switch_node(None).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }
    let c = nmxm.get_compute_nodes_count(None).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm.get_compute_node(None).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }
    let c = nmxm.get_ports_count(None).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm.get_port(None).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm
        .delete_partition("551137c2f9e1fac808a5f572".to_string())
        .await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let members = libnmxm::nmxm_model::PartitionMembers::Empty(None);
    let t = libnmxm::nmxm_model::CreatePartitionRequest {
        name: "empty".to_string(),
        members: Box::new(members),
    };
    let c = nmxm.create_partition(Some(t)).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let members =
        libnmxm::nmxm_model::PartitionMembers::Ids(vec!["551137c2f9e1fac808a5f572".to_string()]);
    let t = libnmxm::nmxm_model::CreatePartitionRequest {
        name: "single_gpu".to_string(),
        members: Box::new(members),
    };
    let c = nmxm.create_partition(Some(t)).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let inner_structs = vec![libnmxm::nmxm_model::PartitionMembersOneOfInner {
        domain_uuid: Uuid::new_v4(),
        chassis_id: 1,
        slot_id: 2,
        host_id: 3,
        device_id: 4,
    }];
    let members = libnmxm::nmxm_model::PartitionMembers::InnerStructs(inner_structs);
    let t = libnmxm::nmxm_model::CreatePartitionRequest {
        name: "gpu_inner_struct".to_string(),
        members: Box::new(members),
    };
    let c = nmxm.create_partition(Some(t)).await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let members =
        libnmxm::nmxm_model::PartitionMembers::Ids(vec!["551137c2f9e1fac808a5f572".to_string()]);
    let req = libnmxm::nmxm_model::UpdatePartitionRequest {
        members: Box::new(members),
    };
    let c = nmxm
        .update_partition("551137c2f9e1fac808a5f572".to_string(), req)
        .await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm
        .get_operation("551137c2f9e1fac808a5f572".to_string())
        .await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm.get_operations_list().await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    let c = nmxm
        .cancel_operation("551137c2f9e1fac808a5f572".to_string())
        .await?;
    json = serde_json::to_string(&c)?;
    if !json.is_empty() {
        println!("{json}");
    }

    Ok(())
}
