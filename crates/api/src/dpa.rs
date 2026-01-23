/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use ::rpc::protos::dpa_rpc::{DpaMetadata, Pfvni, SetVni};
use config_version::ConfigVersion;
use mac_address::MacAddress;
use model::dpa_interface::DpaInterfaceNetworkStatusObservation;
use mqttea::client::{ClientOptions, MqtteaClient};
use mqttea::registry::traits::ProtobufRegistration;
use rumqttc::QoS;
use tokio::time::{Duration, sleep};
use tracing::error;

use crate::api::Api;

pub struct DpaInfo {
    pub subnet_ip: Ipv4Addr,
    pub subnet_mask: i32,
    pub mqtt_client: Option<Arc<MqtteaClient>>,
}

// We just received a message from a DPA via the MQTT broker. Handle that message here.
async fn handle_dpa_message(services: Arc<Api>, message: SetVni, topic: String) {
    let tokens: Vec<&str> = topic.split("/").collect();
    if tokens.len() < 3 {
        error!("handle_dpa_message - unusable topic: {}", topic);
        return;
    }

    let macaddr = match MacAddress::from_str(tokens[2]) {
        Ok(m) => m,
        Err(_e) => {
            error!(
                "handle_dpa_message - Unable to parse mac addr: {}",
                tokens[2]
            );
            return;
        }
    };

    if message.metadata.is_none() || message.pf_info.is_none() {
        error!(
            "handle_dpa_message - message metadata or pf_info is empty: {:#?}",
            message
        );
        return;
    }

    let md = message.clone().metadata.unwrap();

    let mut txn = match services.database_connection.begin().await {
        Ok(t) => t,
        Err(e) => {
            error!("handle_dpa_message - Unable to start txn: {:#?}", e);
            return;
        }
    };

    let mut dpa_ifs = match db::dpa_interface::find_by_mac_addr(&mut txn, &macaddr).await {
        Ok(ifs) => ifs,
        Err(e) => {
            error!("handle_dpa_message -  Error from find_by_mac_addr {e}");
            return;
        }
    };

    if dpa_ifs.len() != 1 {
        error!(
            "handle_dpa_message -  invalid dpa_ifs len from find_by_mac_addr maddr: {} len: {}",
            macaddr,
            dpa_ifs.len()
        );
        return;
    }

    // From the ack received from the DPA, figure out the config version currently
    // known to the DPA. If the DPA went through a powercycle, its config might be
    // invalid and the parsing below will fail.
    let ncv = match ConfigVersion::from_str(&md.revision) {
        Ok(ncv) => ncv,
        Err(e) => {
            error!(
                "handle_dpa_message - Error parsing config version from DPA Ack msg {:#?} {e}",
                message
            );
            ConfigVersion::invalid()
        }
    };

    let dpa_if = dpa_ifs.remove(0);

    let observation = DpaInterfaceNetworkStatusObservation {
        observed_at: chrono::Utc::now(),
        network_config_version: Some(ncv),
    };

    match db::dpa_interface::update_network_observation(&dpa_if, &mut txn, &observation).await {
        Ok(_r) => {
            let res = txn.commit().await;
            if res.is_err() {
                error!(
                    "handle_dpa_message - txn commit error for msg: {:#?} res: {:#?}",
                    message, res
                );
            }
        }
        Err(e) => {
            error!("handle_dpa_message - update_network_observation error: {e}");
        }
    }
}

// Send a SetVni command to the DPA specified by the given macaddress.
// The SetVni command to contain the given vni and revision string.
pub async fn send_dpa_command(
    client: Arc<MqtteaClient>,
    dpa_info: &Arc<DpaInfo>,
    macaddr: String,
    revision: String,
    vni: i32,
) -> Result<(), eyre::Report> {
    let pfvni = Pfvni {
        pf_id: 0,
        mac: macaddr.clone(),
        vni,
        subnet_ip: dpa_info.subnet_ip.to_string(),
        subnet_mask: dpa_info.subnet_mask,
        dhcp_ip: String::new(),
        host_ip: String::new(),
    };

    let mdata = DpaMetadata {
        dpa_id: macaddr.clone(),
        host_id: String::new(),
        revision: revision.clone(),
        transaction: String::new(),
    };

    let svni = SetVni {
        metadata: Some(mdata),
        pf_info: Some(pfvni),
    };

    let maddr = macaddr.replace(":", "");

    let topic = format!("dpa/command/{maddr}/SetVni");

    match client.send_message(&topic, &svni).await {
        Ok(()) => {
            println!("send_dpa_command revision: {revision} vni: {vni}");
        }
        Err(e) => {
            error!(
                "send_dpa_command -  error: {:#?} sending message: {:#?} to topic: {}",
                e, svni, topic
            );
            return Err(eyre::eyre!("send_message error: {e}"));
        }
    }
    Ok(())
}

// Create an MQTTEA client, and start up the thread that will do eventloop polling
// by doing a connect.
pub async fn start_dpa_handler(api_service: Arc<Api>) -> Result<Arc<MqtteaClient>, eyre::Report> {
    let client_id = "forge-client".to_string();

    let default_qos = QoS::AtMostOnce;

    let client = MqtteaClient::new(
        &api_service.runtime_config.mqtt_broker_host().unwrap(),
        api_service.runtime_config.mqtt_broker_port().unwrap(),
        &client_id,
        Some(ClientOptions::default().with_qos(QoS::AtMostOnce)),
    )?;

    client.register_protobuf_message::<SetVni>("SetVni").await?;

    let ns = "dpa/ack/#".to_string();

    client.subscribe(&ns, default_qos).await?;

    let services = api_service.clone();

    client
        .on_message(move |_client, message: SetVni, topic| {
            let value = services.clone();
            async move {
                if let Err(e) = tokio::spawn(async move {
                    handle_dpa_message(value, message, topic).await;
                })
                .await
                {
                    println!("handle_dpa_message failed: {e}");
                }
            }
        })
        .await;

    client.connect().await?;

    // Stats monitoring loop
    let mut last_processed = 0;
    let mut last_sent = 0;

    let stat_client = client.clone();

    tokio::spawn(async move {
        loop {
            let queue_stats = stat_client.queue_stats();
            let publish_stats = stat_client.publish_stats();

            // Only show stats if they changed
            if queue_stats.total_processed != last_processed
                || publish_stats.total_published != last_sent
            {
                println!(
                    "Stats: {} received, {} sent, {} pending",
                    queue_stats.total_processed,
                    publish_stats.total_published,
                    queue_stats.pending_messages
                );
                last_processed = queue_stats.total_processed;
                last_sent = publish_stats.total_published;
            }

            sleep(Duration::from_secs(5)).await;
        }
    });

    Ok(client)
}
