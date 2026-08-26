// SPDX-FileCopyrightText: Copyright (c) 2026 MIRANTIS, INC. & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

use ::rpc::forge as rpc;
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

/// Receive a periodic LLDP neighbor report from a running agent or scout.
pub(crate) async fn report_lldp_neighbors(
    _api: &Api,
    request: Request<rpc::LldpNeighborReport>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);

    let request = request.into_inner();
    let machine_id = convert_and_log_machine_id(request.machine_id.as_ref())?;

    tracing::debug!(
        %machine_id,
        interfaces = request.interfaces.len(),
        "Received LLDP neighbor report (not persisted yet)"
    );
    // TODO Add handling logic in the next PR
    Ok(Response::new(()))
}
