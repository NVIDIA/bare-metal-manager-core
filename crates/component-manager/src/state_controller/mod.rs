// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Component Manager state controller wrapper backends.
//!
//! These backends implement the same `PowerShelfManager` and `NvSwitchManager`
//! traits as the direct backends (`NsmBackend`, `PsmBackend`, `RmsBackend`),
//! so they plug straight into `ComponentManager` via config. The difference:
//! instead of dispatching directly to a device, they resolve the affected
//! endpoints to a single rack, build a `model::rack::MaintenanceScope`
//! carrying the device IDs and a single `model::rack::MaintenanceActivity`,
//! and persist it into `racks.config.maintenance_requested`.
//!
//! The rack state controller picks the request up on its next iteration and
//! drives the work. When it's time to actually touch hardware, it can reach
//! through the wrapper's `direct` field to the underlying backend; this
//! layer only records intent.
//!
//! Calls that don't map cleanly to rack-level maintenance (reading firmware
//! status, listing firmware catalogs, per-device inventory) are passed
//! through to the wrapped direct backend.

use std::collections::HashSet;

use carbide_uuid::rack::RackId;

use crate::error::ComponentManagerError;

pub mod nv_switch;
pub mod power_shelf;

pub use nv_switch::StateControllerNvSwitch;
pub use power_shelf::StateControllerPowerShelf;

/// Returns the single rack_id every endpoint agrees on.
///
/// Errors if any endpoint has a `None` rack_id (because we can't
/// schedule maintenance on a device we don't know rack info about),
/// OR or if the endpoints disagree on which rack they belong to.
///
/// A single component-manager request must target exactly one
/// rack because `MaintenanceScope` lives on one `RackConfig`.
///
/// Maybe we can change this later, but right now the idea is we
/// will get a bunch of devices we want to include in a maintenance
/// request, so we want to resolve the rack_id for each device,
/// make sure they all have a rack_id, and make sure all of the
/// rack_id's match.
pub(crate) fn unique_rack_id<'a>(
    rack_ids: impl IntoIterator<Item = Option<&'a RackId>>,
    device_kind: &'static str,
) -> Result<RackId, ComponentManagerError> {
    let mut unique: HashSet<RackId> = HashSet::new();
    let mut missing = false;
    for rack in rack_ids {
        match rack {
            Some(r) => {
                unique.insert(r.clone());
            }
            None => missing = true,
        }
    }
    if missing {
        return Err(ComponentManagerError::InvalidArgument(format!(
            "one or more {device_kind} have no rack_id; cannot schedule rack maintenance",
        )));
    }
    if unique.len() > 1 {
        return Err(ComponentManagerError::InvalidArgument(format!(
            "{device_kind} span {} racks; component-manager requests must target a single rack",
            unique.len()
        )));
    }
    unique.into_iter().next().ok_or_else(|| {
        ComponentManagerError::InvalidArgument(format!(
            "no resolved {device_kind} to schedule maintenance for",
        ))
    })
}
