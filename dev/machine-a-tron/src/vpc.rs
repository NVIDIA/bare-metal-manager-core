use crate::{
    config::MachineATronContext,
    tui::{UiUpdate, VpcDetails},
};
use ::rpc::Timestamp;
use forge_uuid::vpc::VpcId;
use std::fmt::Debug;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct Vpc {
    pub vpc_id: VpcId,
    pub app_context: Arc<MachineATronContext>,

    pub vpc_name: String,

    pub logs: Vec<String>,

    _created: Option<Timestamp>,
}

impl Vpc {
    pub async fn new(
        app_context: Arc<MachineATronContext>,
        ui_event_tx: Option<tokio::sync::mpsc::Sender<UiUpdate>>,
    ) -> Self {
        // TODO: Add error handling when vpc creation fails.
        let vpc = app_context.api_client().create_vpc().await.unwrap();

        let new_vpc = Vpc {
            vpc_id: vpc.id.expect("VPC must have an ID."),
            app_context,
            vpc_name: vpc.name,
            logs: Vec::default(),
            _created: vpc.created,
        };

        let details = VpcDetails::from(&new_vpc);
        if let Some(ui_event_tx) = ui_event_tx.as_ref() {
            _ = ui_event_tx
                .send(UiUpdate::Vpc(details))
                .await
                .inspect_err(|e| tracing::warn!("Error sending TUI event: {}", e));
        }

        new_vpc
    }
}
