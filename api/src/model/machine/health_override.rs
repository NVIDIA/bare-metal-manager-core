use std::collections::BTreeMap;

use health_report::{HealthReport, OverrideMode};
use serde::{Deserialize, Serialize};

/// All health report overrides stored as JSON in postgres.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HealthReportOverrides {
    /// Stores the "replace" override
    /// The "replace" mode was called "override" in the past
    pub replace: Option<HealthReport>,
    /// A map from the health report source to the health report
    pub merges: BTreeMap<String, HealthReport>,
}

impl HealthReportOverrides {
    pub fn create_iter(self) -> impl Iterator<Item = (HealthReport, OverrideMode)> {
        self.merges
            .into_values()
            .map(|r| (r, OverrideMode::Merge))
            .chain(self.replace.map(|r| (r, OverrideMode::Replace)))
    }
}
