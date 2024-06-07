/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;

use askama::Template;
use axum::extract::State as AxumState;
use axum::response::{Html, IntoResponse};
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use http::StatusCode;
use rpc::forge as forgerpc;

use super::filters;
use crate::api::Api;
use crate::web::machine;

#[derive(Template)]
#[template(path = "dpu_versions.html")]
struct DpuVersions {
    machines: Vec<Row>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Row {
    id: String,
    state: String,
    dpu_type: String,
    firmware_version: String,
    bmc_version: String,
    bios_version: String,
    hbn_version: String,
}

impl From<forgerpc::Machine> for Row {
    fn from(machine: forgerpc::Machine) -> Self {
        let state = match machine.state.split_once(' ') {
            Some((state, _)) => state.to_owned(),
            None => machine.state,
        };

        Row {
            id: machine.id.unwrap_or_default().id,
            dpu_type: machine
                .discovery_info
                .as_ref()
                .and_then(|di| di.dmi_data.as_ref())
                .map(|dmi_data| dmi_data.product_name.clone())
                .unwrap_or_default(),
            state: state.to_owned(),
            firmware_version: machine
                .discovery_info
                .as_ref()
                .and_then(|di| di.dpu_info.as_ref())
                .map(|dpu| dpu.firmware_version.clone())
                .unwrap_or_default(),
            bmc_version: machine
                .bmc_info
                .as_ref()
                .and_then(|bmc| bmc.firmware_version.clone())
                .unwrap_or_default(),
            bios_version: machine
                .discovery_info
                .as_ref()
                .and_then(|di| di.dmi_data.as_ref())
                .map(|dmi_data| dmi_data.bios_version.clone())
                .unwrap_or_default(),
            hbn_version: machine
                .inventory
                .and_then(|inv| {
                    inv.components
                        .iter()
                        .find(|c| c.name == "doca_hbn")
                        .map(|c| c.version.clone())
                })
                .unwrap_or_default(),
        }
    }
}

pub async fn list_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> impl IntoResponse {
    let mut machines = match machine::fetch_machines(state, true).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "find_machines");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new()));
        }
    };
    machines
        .machines
        .retain(|m| m.machine_type == forgerpc::MachineType::Dpu as i32);

    let tmpl = DpuVersions {
        machines: machines.machines.into_iter().map(Row::from).collect(),
    };
    (StatusCode::OK, Html(tmpl.render().unwrap()))
}
