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

//! Test-only helpers. Gated behind the `test-support` feature so this never
//! compiles into a production build.

use std::sync::Arc;

use nv_redfish::{Bmc, Resource, ServiceRoot};

use crate::chassis::ExploredChassisCollection;
use crate::computer_system::{self, ExploredComputerSystem};
use crate::{Config, Error, build_chassis_explore_config, hw, hw_type};

/// Resolve the [`hw::HwType`] for an endpoint, running only the chassis +
/// computer-system exploration that detection depends on.
///
/// This performs the same detection as `nv_generate_exploration_report` but
/// returns the resolved platform type directly. Tests use it to assert the
/// detected platform: the full report only surfaces the derived BMC vendor (via
/// [`hw::HwType::bmc_vendor`]), and several distinct platforms share a vendor
/// (e.g. `Gb200` and `DgxGb300` both map to `Nvidia`, `Supermicro` and
/// `SupermicroGb300` both map to `Supermicro`), so a vendor assertion cannot
/// prove which detection arm was taken.
///
/// Not part of the production API: it re-runs the chassis/system exploration and
/// is only meaningful against a mock BMC.
pub async fn detect_hw_type<B: Bmc>(
    mut root: Arc<ServiceRoot<B>>,
    config: &Config<'_, B>,
) -> Result<Option<hw::HwType>, Error<B>> {
    let chassis_explore_config = build_chassis_explore_config(&root);
    let explored_chassis =
        ExploredChassisCollection::explore(&root, &chassis_explore_config).await?;

    if explored_chassis.is_bluefield2() {
        root = root.as_ref().clone().restrict_expand().into();
    }

    // Mirrors nv_generate_exploration_report's system selection.
    let mut systems_iter = root
        .systems()
        .await
        .map_err(Error::nv_redfish("systems"))?
        .ok_or_else(Error::bmc_not_provided("systems"))?
        .members()
        .await
        .map_err(Error::nv_redfish("systems members"))?
        .into_iter();
    let first_system = systems_iter
        .next()
        .ok_or_else(Error::bmc_not_provided("at least one computer system"))?;
    let other_system_with_bios = systems_iter.find(|system| system.raw().bios.is_some());
    let system = other_system_with_bios.unwrap_or(first_system);

    let is_bluefield_system = system.id().into_inner() == "Bluefield";
    let system_explore_config = computer_system::Config {
        need_oem_nvidia_bluefield: is_bluefield_system,
        ignore_500_on_bios_fetch: is_bluefield_system,
        retry_404_on_eth_interfaces: is_bluefield_system,
        need_boot_options: !explored_chassis.is_bluefield4(),
        explore: config,
    };
    let explored_system = ExploredComputerSystem::explore(system, &system_explore_config).await?;

    Ok(hw_type(&root, &explored_system, &explored_chassis))
}
