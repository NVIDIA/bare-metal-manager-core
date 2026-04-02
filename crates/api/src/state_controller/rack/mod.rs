/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! State Controller implementation for Racks.

use carbide_uuid::rack::RackId;
use model::rack::RackConfig;
use model::rack_type::RackCapabilitiesSet;

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::state_handler::StateHandlerContext;

pub mod context;
pub mod created;
pub mod deleting;
pub mod discovering;
pub mod error_state;
pub mod handler;
pub mod io;
pub mod maintenance;
pub mod ready;
pub mod rv;
pub mod validating;

/// Resolves the `RackCapabilitiesSet` for a rack by looking up its `rack_type`
/// from the runtime config. Returns `None` with a log message if the rack has
/// no `rack_type` or the type is unknown.
pub(crate) fn resolve_capabilities<'a>(
    id: &RackId,
    config: &RackConfig,
    ctx: &'a StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Option<&'a RackCapabilitiesSet> {
    let rack_type = match config.rack_type.as_deref() {
        Some(rt) => rt,
        None => {
            tracing::info!("Rack {} has no rack_type configured", id);
            return None;
        }
    };

    match ctx.services.site_config.rack_types.get(rack_type) {
        Some(caps) => Some(caps),
        None => {
            tracing::warn!("Rack {} has unknown rack_type '{}'", id, rack_type);
            None
        }
    }
}
