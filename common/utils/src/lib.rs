pub mod cmd;
pub mod managed_host_display;
pub use managed_host_display::{get_managed_host_output, ManagedHostOutput};
pub mod models;

/// A string to display to the user. Either the 'reason' or 'err' field, or None.
pub fn reason_to_user_string(p: &rpc::forge::ControllerStateReason) -> Option<String> {
    use rpc::forge::ControllerStateOutcome::*;
    let Ok(outcome) = rpc::forge::ControllerStateOutcome::try_from(p.outcome) else {
        tracing::error!("Invalid rpc::forge::ControllerStateOutcome i32, should be impossible.");
        return None;
    };
    match outcome {
        Transition | DoNothing | Todo => None,
        Wait | Error => p.outcome_msg.clone(),
    }
}
