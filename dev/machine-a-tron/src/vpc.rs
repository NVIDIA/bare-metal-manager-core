use std::fmt::Debug;

use ::rpc::Timestamp;

use uuid::Uuid;

use crate::{
    api_client,
    config::{MachineATronContext, MachineConfig},
    tui::{UiEvent, VpcDetails},
};

#[derive(Debug, Clone)]
pub struct Vpc {
    pub vpc_id: Uuid,
    pub config: MachineConfig,
    pub app_context: MachineATronContext,

    pub vpc_name: String,

    pub logs: Vec<String>,

    _created: Option<Timestamp>,
}

impl Vpc {
    pub async fn new(
        app_context: MachineATronContext,
        config: MachineConfig,
        ui_event_tx: Option<tokio::sync::mpsc::Sender<UiEvent>>,
    ) -> Self {
        let vpc = api_client::create_vpc(&app_context).await.unwrap();

        let new_vpc = Vpc {
            vpc_id: uuid::Uuid::parse_str(&vpc.id.unwrap().value).expect("REASON"),
            config,
            app_context,
            vpc_name: vpc.name,
            logs: Vec::default(),
            _created: vpc.created,
        };

        let details = VpcDetails::from(&new_vpc);
        if let Some(ui_event_tx) = ui_event_tx.as_ref() {
            _ = ui_event_tx
                .send(UiEvent::VpcUpdate(details))
                .await
                .inspect_err(|e| tracing::warn!("Error sending TUI event: {}", e));
        }

        new_vpc
    }
}
