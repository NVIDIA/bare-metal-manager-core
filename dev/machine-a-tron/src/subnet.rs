use ::rpc::Timestamp;
use std::fmt::Debug;
use uuid::Uuid;

use crate::{
    api_client,
    config::{MachineATronContext, MachineConfig},
    tui::{SubnetDetails, UiEvent},
};
use tonic::Status;

#[derive(Debug, Clone)]
pub struct Subnet {
    pub segment_id: Uuid,
    pub config: MachineConfig,
    pub app_context: MachineATronContext,

    pub vpc_id: Uuid,
    pub prefixes: Vec<String>,
    pub logs: Vec<String>,

    _created: Option<Timestamp>,
}

impl Subnet {
    pub async fn new(
        app_context: MachineATronContext,
        config: MachineConfig,
        ui_event_tx: Option<tokio::sync::mpsc::Sender<UiEvent>>,
        vpc_name: &String,
    ) -> Result<Subnet, Status> {
        let network_segment = api_client::create_network_segment(&app_context, vpc_name)
            .await
            .map_err(|e| {
                tracing::error!("Error creating network segment: {}", e);
                Status::internal("Failed to create network segment.")
            })?;

        let new_subnet = Subnet {
            segment_id: uuid::Uuid::parse_str(&network_segment.id.unwrap().value)
                .expect("Segment must have an ID."),
            vpc_id: uuid::Uuid::parse_str(&network_segment.vpc_id.unwrap().value)
                .expect("Segment must have a VPC_ID."),
            config,
            app_context,
            prefixes: network_segment
                .prefixes
                .iter()
                .map(|s| s.prefix.clone())
                .collect(),
            logs: Vec::default(),
            _created: network_segment.created,
        };

        let details = SubnetDetails::from(&new_subnet);
        if let Some(ui_event_tx) = ui_event_tx.as_ref() {
            _ = ui_event_tx
                .send(UiEvent::SubnetUpdate(details))
                .await
                .inspect_err(|e| tracing::warn!("Error sending TUI event: {}", e));
        }

        Ok(new_subnet)
    }
}
