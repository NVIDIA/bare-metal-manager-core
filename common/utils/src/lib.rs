pub mod admin_cli;
pub mod cmd;
pub mod managed_host_display;
pub use managed_host_display::{get_managed_host_output, ManagedHostMetadata, ManagedHostOutput};
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

pub fn has_duplicates<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + std::hash::Hash,
{
    let mut uniq = std::collections::HashSet::new();
    !iter.into_iter().all(move |x| uniq.insert(x))
}

#[cfg(test)]
mod tests {
    pub use super::*;
    #[test]
    pub fn test_has_duplicates() {
        assert!(!has_duplicates(vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string()
        ]));
        assert!(has_duplicates(vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "2".to_string(),
            "4".to_string()
        ]));
        assert!(!has_duplicates(vec![1, 2, 3, 4, 5]));
        assert!(has_duplicates(vec![1, 2, 3, 4, 5, 1]));

        let v1 = vec!["1", "3"];
        // call  has_duplicates using ref
        println!("{}", has_duplicates(&v1));
        assert_eq!(v1.len(), 2);
    }
}
