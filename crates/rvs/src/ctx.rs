use crate::client::NiccClient;
use crate::config::Config;
use crate::scenario::Scenario;

/// Top-level RVS runtime context -- passed to all major routines.
///
/// Bundles the NICC client, loaded scenarios, and service config so individual
/// routines don't need to accept each piece separately.
pub struct RvsCtx {
    pub nicc: NiccClient,
    pub scenarios: Vec<Scenario>,
    pub cfg: Config,
    /// Dev/test only: load SOT JSON from this file path instead of calling
    /// gRPC. Set in `test-artifact-cache`; always `None` in production.
    pub sot_override_path: Option<String>,
}
