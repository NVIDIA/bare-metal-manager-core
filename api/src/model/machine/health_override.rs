use std::collections::BTreeMap;

use health_report::{HealthReport, OverrideMode};
use serde::{Deserialize, Serialize};

/// All health report overrides stored as JSON in postgres.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct HealthReportOverrides {
    pub r#override: Option<HealthReport>,
    /// A map from the health report source to the health report
    pub merges: BTreeMap<String, HealthReport>,
}

impl HealthReportOverrides {
    pub fn create_iter(self) -> impl Iterator<Item = (HealthReport, OverrideMode)> {
        self.merges
            .into_values()
            .map(|r| (r.clone(), OverrideMode::Merge))
            .chain(self.r#override.map(|r| (r, OverrideMode::Override)))
    }
}
