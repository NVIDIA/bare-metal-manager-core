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

use carbide_uuid::power_shelf::PowerShelfId;
use clap::Parser;
use rpc::forge as forgerpc;

/// Drive one or more power shelves into maintenance and request a power
/// operation (PowerOn / PowerOff). All listed power shelves receive the same
/// operation in a single atomic request.
#[derive(Parser, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Args {
    /// Request the listed power shelves to power on.
    PowerOn(MaintenancePowerArgs),
    /// Request the listed power shelves to power off.
    PowerOff(MaintenancePowerArgs),
}

#[derive(Parser, Debug)]
pub struct MaintenancePowerArgs {
    /// One or more Power Shelf IDs. Repeat the flag or pass multiple values:
    ///   --power-shelf-id <id1> --power-shelf-id <id2>
    ///   --power-shelf-id <id1> <id2>
    #[clap(
        long = "power-shelf-id",
        visible_alias = "id",
        required(true),
        num_args = 1..,
        value_name = "POWER_SHELF_ID",
        help = "One or more Power Shelf IDs to drive into maintenance"
    )]
    pub power_shelf_ids: Vec<PowerShelfId>,

    #[clap(
        long,
        visible_alias = "ref",
        help = "URL of reference (ticket, issue, etc) for this maintenance request"
    )]
    pub reference: Option<String>,
}

impl Args {
    pub fn into_request(self) -> forgerpc::PowerShelfMaintenanceRequest {
        let (operation, args) = match self {
            Args::PowerOn(args) => (forgerpc::PowerShelfMaintenanceOperation::PowerOn, args),
            Args::PowerOff(args) => (forgerpc::PowerShelfMaintenanceOperation::PowerOff, args),
        };
        forgerpc::PowerShelfMaintenanceRequest {
            power_shelf_ids: args.power_shelf_ids,
            operation: operation.into(),
            reference: args.reference,
        }
    }
}
