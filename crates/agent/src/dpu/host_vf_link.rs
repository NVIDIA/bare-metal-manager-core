use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::path::Path;

use eyre::WrapErr;
use itertools::Itertools;

mod parse_hbn_conf;

#[derive(Debug, Eq, PartialEq)]
/// Maps tenant VF IDs to their HBN-owned host representors.
struct VfInterfaceMap {
    representor_names: HashMap<u32, String>,
}

impl VfInterfaceMap {
    /// Loads a validated host VF ownership mapping from an HBN configuration file.
    async fn load_from(path: impl AsRef<Path>) -> eyre::Result<Self> {
        let path = path.as_ref();
        let contents = tokio::fs::read_to_string(path)
            .await
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        Self::parse(&contents).wrap_err_with(|| format!("parsing {}", path.display()))
    }

    /// Parses host VF ownership entries from an HBN configuration file.
    ///
    /// An example minimal valid configuration is:
    ///
    /// ```text
    /// [LINK_PROPAGATION]
    /// pf0vf7:pf0vf7_if_r
    /// ```
    fn parse(contents: &str) -> eyre::Result<Self> {
        Ok(Self {
            representor_names: parse_hbn_conf::get_hbn_vf_mapping(contents)?,
        })
    }

    /// Returns the names of every host VF representor owned by this mapping.
    fn managed_host_representors(&self) -> impl Iterator<Item = &str> + '_ {
        self.representor_names.values().map(String::as_str)
    }

    /// Returns the owned host representor associated with a VF ID.
    fn representor_name(&self, vf_id: u32) -> Option<&str> {
        self.representor_names.get(&vf_id).map(String::as_str)
    }

    /// Returns the set of VF IDs accepted by this ownership mapping.
    fn valid_vf_ids(&self) -> HashSet<u32> {
        self.representor_names.keys().copied().collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Describes a concrete administrative state for a managed link.
enum LinkAdminState {
    Up,
    Down,
}

impl LinkAdminState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
        }
    }
}

impl fmt::Display for LinkAdminState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
/// Records the reconciler's estimate of a managed link's administrative state.
enum LinkAdminStateEstimate {
    #[default]
    Unknown,
    Assumed(LinkAdminState),
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Describes the desired administrative state change for one managed link.
struct LinkStateOperation {
    interface: String,
    desired_state: LinkAdminState,
}

impl LinkStateOperation {
    fn new(interface: impl Into<String>, desired_state: LinkAdminState) -> Self {
        Self {
            interface: interface.into(),
            desired_state,
        }
    }
}

/// Reports whether a failed link operation may have changed the link state.
trait LinkStateControllerError: Error + Send + Sync + 'static {
    /// Returns whether the cached administrative state can no longer be trusted.
    fn maybe_obscured_state(&self) -> bool;
}

type BoxedLinkStateControllerError = Box<dyn LinkStateControllerError>;

/// Applies administrative state changes selected by the reconciler.
#[async_trait::async_trait]
trait LinkStateController: fmt::Debug + Send {
    /// Applies one requested administrative state change.
    async fn apply_state_operation(
        &mut self,
        operation: &LinkStateOperation,
    ) -> Result<(), BoxedLinkStateControllerError>;
}

#[derive(Debug, Default)]
/// Tracks link-state estimates and selects representors that still need updates.
struct LinkStateReconciler {
    state_estimates: HashMap<String, LinkAdminStateEstimate>,
}

impl LinkStateReconciler {
    fn new<I, S>(managed_links: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            state_estimates: managed_links
                .into_iter()
                .map(|interface| (interface.into(), LinkAdminStateEstimate::Unknown))
                .collect(),
        }
    }

    fn invalidate_cached_state(&mut self) {
        for estimate in self.state_estimates.values_mut() {
            *estimate = LinkAdminStateEstimate::Unknown;
        }
    }

    fn pending_operations<I, S>(&self, active_links: I) -> Vec<LinkStateOperation>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let active_links = active_links
            .into_iter()
            .map(Into::into)
            .collect::<HashSet<_>>();

        self.state_estimates
            .iter()
            .filter_map(|(interface, estimate)| {
                match (*estimate, active_links.contains(interface)) {
                    (LinkAdminStateEstimate::Assumed(LinkAdminState::Up), true)
                    | (LinkAdminStateEstimate::Assumed(LinkAdminState::Down), false) => None,
                    (_, true) => Some(LinkStateOperation::new(interface, LinkAdminState::Up)),
                    (_, false) => Some(LinkStateOperation::new(interface, LinkAdminState::Down)),
                }
            })
            .collect()
    }

    async fn reconcile_links<I, S>(
        &mut self,
        active_links: I,
        controller: &mut dyn LinkStateController,
    ) -> Result<(), LinkStateReconciliationError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let pending_operations = self.pending_operations(active_links);
        let mut failures = Vec::new();

        for operation in pending_operations {
            match controller.apply_state_operation(&operation).await {
                Ok(()) => {
                    *self
                        .state_estimates
                        .get_mut(&operation.interface)
                        .expect("operation must reference a managed link") =
                        LinkAdminStateEstimate::Assumed(operation.desired_state);
                }
                Err(error) => {
                    if error.maybe_obscured_state() {
                        *self
                            .state_estimates
                            .get_mut(&operation.interface)
                            .expect("operation must reference a managed link") =
                            LinkAdminStateEstimate::Unknown;
                    }
                    failures.push(LinkStateOperationFailure { operation, error });
                }
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(LinkStateReconciliationError { failures })
        }
    }
}

#[derive(Debug)]
/// Associates one failed administrative operation with its controller error.
struct LinkStateOperationFailure {
    operation: LinkStateOperation,
    error: BoxedLinkStateControllerError,
}

impl fmt::Display for LinkStateOperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "interface={} desired_state={} error={}",
            self.operation.interface.as_str(),
            self.operation.desired_state.as_str(),
            self.error
        )
    }
}

#[derive(Debug)]
/// Reports every host VF link operation that failed during one reconciliation.
struct LinkStateReconciliationError {
    failures: Vec<LinkStateOperationFailure>,
}

impl fmt::Display for LinkStateReconciliationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut failures = self.failures.iter().collect::<Vec<_>>();
        failures.sort_by_key(|failure| &failure.operation.interface);
        write!(
            formatter,
            "failed to reconcile host VF links: {}",
            failures.into_iter().join("; ")
        )
    }
}

impl Error for LinkStateReconciliationError {}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    fn vf_map(entries: &[(u32, &str)]) -> VfInterfaceMap {
        VfInterfaceMap {
            representor_names: entries
                .iter()
                .map(|(vf_id, interface)| (*vf_id, (*interface).to_string()))
                .collect(),
        }
    }

    #[test]
    fn retains_configured_host_representor_names() {
        let interface_map = vf_map(&[(7, "pf0vf07"), (1, "pf0vf1")]);
        let mut representors = interface_map
            .managed_host_representors()
            .collect::<Vec<_>>();
        representors.sort();

        assert_eq!(representors, ["pf0vf07", "pf0vf1"]);
    }

    #[derive(Clone, Debug)]
    struct FakeControllerError {
        obscures_state: bool,
        message: &'static str,
    }

    impl fmt::Display for FakeControllerError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.message)
        }
    }

    impl Error for FakeControllerError {}

    impl LinkStateControllerError for FakeControllerError {
        fn maybe_obscured_state(&self) -> bool {
            self.obscures_state
        }
    }

    #[derive(Debug, Default)]
    struct FakeController {
        failures: HashMap<String, VecDeque<FakeControllerError>>,
        operations: Vec<LinkStateOperation>,
    }

    impl FakeController {
        fn fail_once(
            mut self,
            interface: &str,
            obscures_state: bool,
            message: &'static str,
        ) -> Self {
            self.failures
                .entry(interface.to_string())
                .or_default()
                .push_back(FakeControllerError {
                    obscures_state,
                    message,
                });
            self
        }
    }

    #[async_trait::async_trait]
    impl LinkStateController for FakeController {
        async fn apply_state_operation(
            &mut self,
            operation: &LinkStateOperation,
        ) -> Result<(), BoxedLinkStateControllerError> {
            self.operations.push(operation.clone());
            match self.failures.get_mut(&operation.interface) {
                Some(failures) if !failures.is_empty() => {
                    Err(Box::new(failures.pop_front().unwrap()))
                }
                _ => Ok(()),
            }
        }
    }

    fn sorted_operations(operations: &[LinkStateOperation]) -> Vec<LinkStateOperation> {
        let mut operations = operations.to_vec();
        operations.sort_by(|left, right| left.interface.cmp(&right.interface));
        operations
    }

    #[tokio::test]
    async fn reconciles_startup_attach_detach_and_cached_noop() {
        let mut reconciler = LinkStateReconciler::new(["pf0vf0", "pf0vf1"]);
        let mut controller = FakeController::default();

        reconciler
            .reconcile_links(["pf0vf0"], &mut controller)
            .await
            .unwrap();
        assert_eq!(
            sorted_operations(&controller.operations),
            vec![
                LinkStateOperation::new("pf0vf0", LinkAdminState::Up),
                LinkStateOperation::new("pf0vf1", LinkAdminState::Down),
            ]
        );

        controller.operations.clear();
        reconciler
            .reconcile_links(["pf0vf0"], &mut controller)
            .await
            .unwrap();
        assert!(controller.operations.is_empty());

        reconciler.invalidate_cached_state();
        reconciler
            .reconcile_links(["pf0vf0"], &mut controller)
            .await
            .unwrap();
        assert_eq!(
            sorted_operations(&controller.operations),
            vec![
                LinkStateOperation::new("pf0vf0", LinkAdminState::Up),
                LinkStateOperation::new("pf0vf1", LinkAdminState::Down),
            ]
        );

        controller.operations.clear();
        reconciler
            .reconcile_links(["pf0vf1"], &mut controller)
            .await
            .unwrap();
        assert_eq!(
            sorted_operations(&controller.operations),
            vec![
                LinkStateOperation::new("pf0vf0", LinkAdminState::Down),
                LinkStateOperation::new("pf0vf1", LinkAdminState::Up),
            ]
        );
    }

    #[tokio::test]
    async fn retains_successes_and_retries_only_failed_links() {
        let mut reconciler = LinkStateReconciler::new(["pf0vf0", "pf0vf1"]);
        let mut controller = FakeController::default().fail_once("pf0vf1", true, "denied");

        let error = reconciler
            .reconcile_links(["pf0vf0", "pf0vf1"], &mut controller)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("interface=pf0vf1"));

        controller.operations.clear();
        reconciler
            .reconcile_links(["pf0vf0", "pf0vf1"], &mut controller)
            .await
            .unwrap();
        assert_eq!(
            controller.operations,
            vec![LinkStateOperation::new("pf0vf1", LinkAdminState::Up)]
        );
    }

    #[tokio::test]
    async fn failure_classification_controls_state_estimate() {
        for (obscures_state, expect_retry) in [(false, false), (true, true)] {
            let mut reconciler = LinkStateReconciler::new(["pf0vf0"]);
            let mut controller = FakeController::default();
            reconciler
                .reconcile_links(["pf0vf0"], &mut controller)
                .await
                .unwrap();

            controller =
                FakeController::default().fail_once("pf0vf0", obscures_state, "operation failed");
            reconciler
                .reconcile_links(Vec::<&str>::new(), &mut controller)
                .await
                .unwrap_err();

            controller.operations.clear();
            reconciler
                .reconcile_links(["pf0vf0"], &mut controller)
                .await
                .unwrap();
            assert_eq!(
                !controller.operations.is_empty(),
                expect_retry,
                "obscures_state={obscures_state}"
            );
        }
    }

    #[tokio::test]
    async fn formats_aggregated_failures_in_interface_order() {
        let mut reconciler = LinkStateReconciler::new(["pf0vf2", "pf0vf10"]);
        let mut controller = FakeController::default()
            .fail_once("pf0vf2", true, "second")
            .fail_once("pf0vf10", true, "first");

        let error = reconciler
            .reconcile_links(["pf0vf2", "pf0vf10"], &mut controller)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.find("pf0vf10").unwrap() < error.find("pf0vf2").unwrap());
        assert!(error.contains("desired_state=up"));
    }
}
