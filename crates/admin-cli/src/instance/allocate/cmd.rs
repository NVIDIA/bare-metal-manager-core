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

use std::collections::VecDeque;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};

use super::args::Args;
use crate::instance::common::GlobalOptions;
use crate::machine;
use crate::rpc::ApiClient;

pub async fn allocate(
    api_client: &ApiClient,
    allocate_request: Args,
    opts: GlobalOptions<'_>,
) -> CarbideCliResult<()> {
    if opts.cloud_unsafe_op.is_none() {
        return Err(CarbideCliError::GenericError(
            "Operation not allowed due to potential inconsistencies with cloud database."
                .to_owned(),
        ));
    }

    let number = allocate_request.number.unwrap_or(1);

    // Validate: --transactional requires --number > 1
    if allocate_request.transactional && number <= 1 {
        return Err(CarbideCliError::GenericError(
            "--transactional requires --number > 1".to_owned(),
        ));
    }

    let mut machine_ids: VecDeque<_> = if !allocate_request.machine_id.is_empty() {
        allocate_request.machine_id.iter().copied().collect()
    } else {
        api_client
            .0
            .find_machine_ids(::rpc::forge::MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            })
            .await?
            .machine_ids
            .into()
    };

    let min_interface_count = if !allocate_request.vpc_prefix_id.is_empty() {
        allocate_request.vpc_prefix_id.len()
    } else {
        allocate_request.subnet.len()
    };

    if allocate_request.transactional {
        // Batch mode: all-or-nothing
        let mut requests = Vec::new();
        for i in 0..number {
            let Some(machine) =
                machine::get_next_free_machine(api_client, &mut machine_ids, min_interface_count)
                    .await
            else {
                return Err(CarbideCliError::GenericError(format!(
                    "Need {} machines but only {} available.",
                    number, i
                )));
            };

            let request = api_client
                .build_instance_request(
                    machine,
                    &allocate_request,
                    &format!("{}_{}", allocate_request.prefix_name, i),
                    opts.cloud_unsafe_op.clone(),
                )
                .await?;
            requests.push(request);
        }

        match api_client.allocate_instances(requests).await {
            Ok(instances) => {
                tracing::info!(
                    "Batch allocate was successful. Created {} instances.",
                    instances.len()
                );
                for instance in instances {
                    tracing::info!("  Created: {:?}", instance);
                }
            }
            Err(e) => {
                tracing::error!("Batch allocate failed: {}", e);
            }
        }
    } else {
        // Sequential mode: partial success allowed
        for i in 0..number {
            let Some(machine) =
                machine::get_next_free_machine(api_client, &mut machine_ids, min_interface_count)
                    .await
            else {
                tracing::error!("No available machines.");
                break;
            };

            match api_client
                .allocate_instance(
                    machine,
                    &allocate_request,
                    &format!("{}_{}", allocate_request.prefix_name, i),
                    opts.cloud_unsafe_op.clone(),
                )
                .await
            {
                Ok(i) => {
                    tracing::info!("allocate was successful. Created instance: {:?} ", i);
                }
                Err(e) => {
                    tracing::info!("allocate failed with {} ", e);
                }
            };
        }
    }
    Ok(())
}
