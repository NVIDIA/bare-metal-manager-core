/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This file contains code that interacts with the SVPC agent on the DPA
 * using MQTT =  Code to send commands via MQTT, code that handles messages
 * received from the DPA via MQTT and code to start the MQTT client.
 */

use std::str::FromStr;
use std::sync::Arc;

use carbide_dpa::rpc::SetVni;
use carbide_uuid::spx::NULL_SPX_PARTITION_ID;
use config_version::ConfigVersion;
use db::ObjectColumnFilter;
use mac_address::MacAddress;
use model::instance::config::spx::SpxAttachmentType;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::spx::{MachineSpxAttachmentStatusObservation, MachineSpxStatusObservation};
use mqttea::client::{ClientOptions, MqtteaClient};
use mqttea::registry::traits::ProtobufRegistration;
use rumqttc::QoS;
use tokio::task::JoinSet;
use tokio::time::{Duration, sleep};
use tokio_util::sync::CancellationToken;

use crate::api::Api;

// We just received a message from a DPA via the MQTT broker. Handle that message here.
// We figure out the DPA interface belonging to this message and update the observed
// status of the DPA in the machine's spx_status_observation field.
async fn handle_dpa_message(services: Arc<Api>, message: SetVni, topic: String) {
    let tokens: Vec<&str> = topic.split("/").collect();
    if tokens.len() < 3 {
        tracing::error!(
            "handle_dpa_message: token len {} is unusable topic: {}",
            tokens.len(),
            topic
        );
        return;
    }

    let macaddr = match MacAddress::from_str(tokens[2]) {
        Ok(m) => m,
        Err(_e) => {
            tracing::error!(
                "handle_dpa_message: Unable to parse mac addr: {}",
                tokens[2]
            );
            return;
        }
    };

    if message.metadata.is_none() || message.pf_info.is_none() {
        tracing::error!(
            "handle_dpa_message: message metadata or pf_info is empty: {:#?}",
            message
        );
        return;
    }

    let md = message.clone().metadata.unwrap();

    let mut txn = match services.database_connection.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("handle_dpa_message: Unable to start txn: {:#?}", e);
            return;
        }
    };

    let mut dpa_ifs = match db::dpa_interface::find_by_mac_addr(txn.as_mut(), &macaddr).await {
        Ok(ifs) => ifs,
        Err(e) => {
            tracing::error!(
                "handle_dpa_message: Error for mac {macaddr} from find_by_mac_addr {:#?}",
                e
            );
            return;
        }
    };

    if dpa_ifs.len() != 1 {
        tracing::error!(
            "handle_dpa_message: invalid dpa_ifs len from find_by_mac_addr maddr {macaddr} len {:#?}",
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
            tracing::error!(
                "handle_dpa_message: Error parsing config version from DPA Ack msg {:#?} {:#?}",
                message,
                e
            );
            ConfigVersion::invalid()
        }
    };

    // We checked that pf_info is not None above, so unwrap is safe.
    // If vni is non-zero, then we are in a tenancy and the partition_id is not None.
    // We need to get the partition_id correponding to this vni from the database.
    let vni = message.pf_info.as_ref().unwrap().vni;

    let mut spx_partition_id = NULL_SPX_PARTITION_ID;

    if vni != 0 {
        let partition = match db::spx_partition::find_by(
            txn.as_mut(),
            ObjectColumnFilter::List(db::spx_partition::VniColumn, &[vni]),
        )
        .await
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    "handle_dpa_message: Error for vni {vni} from find_by_vni {:#?}",
                    e
                );
                return;
            }
        };

        if partition.len() != 1 {
            tracing::error!("handle_dpa_message: SPX partition with vni {vni} is not found");
            return;
        }

        let spx_partition = &partition[0];
        spx_partition_id = spx_partition.id;

        tracing::debug!(
            "handle_dpa_message: SPX partition with vni {vni} found: {:#?}",
            spx_partition
        );
    } else {
        tracing::debug!(
            "handle_dpa_message: received vni 0 in DPA message {:#?}",
            message
        );
    }

    let dpa_if = dpa_ifs.remove(0);

    let at_status = MachineSpxAttachmentStatusObservation {
        mac_address: macaddr,
        partition_id: Some(spx_partition_id),
        attachment_type: Some(SpxAttachmentType::Physical), // Only Physical attachments are supported at the moment
        virtual_function_id: None,
        config_version: Some(ncv),
        observed_at: chrono::Utc::now(),
    };

    // Get the machine corresponding to the DPA interface.
    // The machine entry needs to be obtained with FOR UPDATE to avoid race conditions.
    let machine = match db::machine::find_one(
        txn.as_mut(),
        &dpa_if.machine_id,
        MachineSearchConfig {
            for_update: true,
            ..Default::default()
        },
    )
    .await
    {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("handle_dpa_message: Error for machine {:#?}", e);
            return;
        }
    };

    if machine.is_none() {
        tracing::error!(
            "handle_dpa_message: Machine not found for DPA interface {:#?}",
            dpa_if
        );
        return;
    }

    let machine = machine.unwrap();

    let cur_spx_status_observations = machine.spx_status_observation.unwrap_or_default();
    let mut new_spx_status_observations = MachineSpxStatusObservation::default();

    let mut add_new_observation = true;

    for obs in cur_spx_status_observations.spx_attachments.iter() {
        if obs.mac_address != macaddr {
            new_spx_status_observations
                .spx_attachments
                .push(obs.clone());
        } else if obs.observed_at < at_status.observed_at {
            new_spx_status_observations
                .spx_attachments
                .push(at_status.clone());
            add_new_observation = false;
        }
    }

    if add_new_observation {
        new_spx_status_observations
            .spx_attachments
            .push(at_status.clone());
    }

    match db::machine::update_spx_status_observation(
        &mut txn,
        &dpa_if.machine_id,
        &new_spx_status_observations,
    )
    .await
    {
        Ok(_r) => {
            let res = txn.commit().await;
            if res.is_err() {
                tracing::error!(
                    "handle_dpa_message: txn commit error for msg {:#?} res {:#?}",
                    message,
                    res
                );
            }
        }
        Err(e) => {
            tracing::error!(
                "handle_dpa_message: update_network_observation error for msg {:#?} {:#?}",
                message,
                e
            );
        }
    }
}

// Create an MQTTEA client, and start up the thread that will do eventloop polling
// by doing a connect.
pub async fn start_dpa_handler(
    join_set: &mut JoinSet<()>,
    api_service: Arc<Api>,
    cancel_token: CancellationToken,
) -> Result<Arc<MqtteaClient>, eyre::Report> {
    let client_id = "forge-client".to_string();

    let default_qos = QoS::AtMostOnce;

    let options = {
        let defaults = ClientOptions::default().with_qos(default_qos);
        if let Some(ref dpa_config) = api_service.runtime_config.dpa_config
            && let Some(provider) = crate::auth::mqtt_auth::build_credentials_provider(
                &dpa_config.auth,
                forge_secrets::credentials::CredentialKey::MqttAuth {
                    credential_type: forge_secrets::credentials::MqttCredentialType::Dpa,
                },
                api_service.credential_manager.clone(),
            )
            .await?
        {
            defaults.with_credentials_provider(provider)
        } else {
            defaults
        }
    };

    let client = MqtteaClient::new(
        &api_service.runtime_config.mqtt_broker_host().unwrap(),
        api_service.runtime_config.mqtt_broker_port().unwrap(),
        &client_id,
        Some(options),
    )
    .await?;

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
                    tracing::error!("handle_dpa_message failed: {e}");
                }
            }
        })
        .await;

    client.connect().await?;

    // Stats monitoring loop
    let mut last_processed = 0;
    let mut last_sent = 0;

    let stat_client = client.clone();

    join_set.spawn(async move {
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

            tokio::select! {
                _ = sleep(Duration::from_secs(5)) => {}
                _ = cancel_token.cancelled() => {
                    break;
                }
            }
        }
    });

    Ok(client)
}
