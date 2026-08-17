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

use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::MachineId;
use clap::{ArgGroup, Parser};
use rpc::forge::ReleaseDpuServiceSyncHoldRequest;
use rpc::forge::release_dpu_service_sync_hold_request::Target;

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

List every machine waiting on a DPUService rollout, longest wait first:
    $ nico-admin-cli dpf service-sync list

Show one host's recorded sync history, including who released each one:
    $ nico-admin-cli dpf service-sync list --machine-id 12345678-1234-5678-90ab-cdef01234567

Release the hold for one or more hosts:
    $ nico-admin-cli dpf service-sync release --machine-id 12345678-1234-5678-90ab-cdef01234567

Release the host running an instance, accepting that its tenant is disrupted:
    $ nico-admin-cli dpf service-sync release --instance-id abcdef01-2345-6789-abcd-ef0123456789

")]
pub(crate) enum Args {
    #[clap(about = "List machines DPF is waiting on before a DPUService rollout")]
    List(List),
    #[clap(about = "Release the DPF maintenance hold blocking a DPUService rollout")]
    Release(Release),
}

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

List every machine waiting on a DPUService rollout, longest wait first:
    $ nico-admin-cli dpf service-sync list

Show one host's recorded sync history, including who released each one:
    $ nico-admin-cli dpf service-sync list --machine-id 12345678-1234-5678-90ab-cdef01234567

")]
pub(crate) struct List {
    #[clap(
        long = "machine-id",
        visible_alias = "id",
        help = "Show this host's recorded history instead of the outstanding worklist"
    )]
    pub(super) machine_id: Option<MachineId>,
}

#[derive(Parser, Debug)]
#[command(group(ArgGroup::new("target").required(true).multiple(false)))]
#[command(after_long_help = "\
EXAMPLES:

Release one host:
    $ nico-admin-cli dpf service-sync release --machine-id 12345678-1234-5678-90ab-cdef01234567

Release several hosts in one call:
    $ nico-admin-cli dpf service-sync release --machine-id 12345678-1234-5678-90ab-cdef01234567 abcdef01-2345-6789-abcd-ef0123456789

Release the host running an instance, accepting that its tenant is disrupted:
    $ nico-admin-cli dpf service-sync release --instance-id abcdef01-2345-6789-abcd-ef0123456789

")]
pub(crate) struct Release {
    /// Hosts to release. A host with a tenant on it is skipped: name that
    /// tenant's instance instead, so the disruption is asked for rather than
    /// stumbled into.
    #[clap(
        long = "machine-id",
        visible_alias = "id",
        num_args = 1..,
        value_name = "MACHINE_ID",
        group = "target",
        help = "One or more host machine ids to release"
    )]
    pub(super) machine_ids: Vec<MachineId>,

    /// Releases the host currently running this instance even though it is
    /// assigned. Naming the instance is the acknowledgement that its tenant will
    /// be disrupted, and covers only this instance.
    #[clap(
        long = "instance-id",
        value_name = "INSTANCE_ID",
        group = "target",
        help = "Release the host running this instance, disrupting its tenant"
    )]
    pub(super) instance_id: Option<InstanceId>,
}

impl From<&Release> for ReleaseDpuServiceSyncHoldRequest {
    fn from(args: &Release) -> Self {
        let target = match args.instance_id {
            Some(instance_id) => Target::InstanceId(instance_id),
            None => Target::MachineIds(::rpc::common::MachineIdList {
                machine_ids: args.machine_ids.clone(),
            }),
        };
        Self {
            target: Some(target),
        }
    }
}
