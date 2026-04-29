mod io;

pub use io::{plan, submit_report, validate_partition};

use crate::rack::Tray;

/// A single unit of validation work derived from a partition.
///
/// Stub: will carry partition type (NVL domain / IB fabric), tray IDs, etc.
pub struct ValidationJob {
    pub(crate) trays: Vec<Tray>,
}

pub struct Report {
    trays_cnt: u32,
}

#[allow(dead_code)]
pub struct Reports {
    inner: Vec<Report>,
}
