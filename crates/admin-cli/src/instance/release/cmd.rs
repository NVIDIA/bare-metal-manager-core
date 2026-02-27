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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge::InstanceReleaseRequest;
use carbide_uuid::instance::InstanceId;

use super::args::Args;
use crate::instance::common::GlobalOptions;
use crate::rpc::ApiClient;

pub async fn release(
    api_client: &ApiClient,
    release_request: Args,
    opts: GlobalOptions<'_>,
) -> CarbideCliResult<()> {
    if opts.cloud_unsafe_op.is_none() {
        return Err(CarbideCliError::GenericError(
            "Operation not allowed due to potential inconsistencies with cloud database."
                .to_owned(),
        ));
    }

    let mut instance_ids: Vec<InstanceId> = Vec::new();

    match (
        release_request.instance,
        release_request.machine,
        release_request.label_key,
    ) {
        (Some(instance_id), _, _) => instance_ids.push(
            uuid::Uuid::parse_str(&instance_id)
                .map_err(|e| CarbideCliError::GenericError(e.to_string()))?
                .into(),
        ),
        (_, Some(machine_id), _) => {
            let instances = api_client.0.find_instance_by_machine_id(machine_id).await?;
            if instances.instances.is_empty() {
                return Err(CarbideCliError::GenericError(
                    "No instances assigned to that machine".to_string(),
                ));
            }
            instance_ids.push(instances.instances[0].id.unwrap());
        }
        (_, _, Some(key)) => {
            let instances = api_client
                .get_all_instances(
                    None,
                    None,
                    Some(key),
                    release_request.label_value,
                    None,
                    opts.page_size,
                )
                .await?;
            if instances.instances.is_empty() {
                return Err(CarbideCliError::GenericError(
                    "No instances with the passed label.key exist".to_string(),
                ));
            }
            instance_ids = instances
                .instances
                .iter()
                .filter_map(|instance| instance.id)
                .collect();
        }
        _ => {}
    };
    for instance_id in instance_ids {
        api_client
            .0
            .release_instance(InstanceReleaseRequest {
                id: Some(instance_id),
                issue: None,
                is_repair_tenant: None,
            })
            .await?;
    }
    Ok(())
}
