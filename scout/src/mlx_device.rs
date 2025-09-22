/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::cfg::Options;
use crate::client;
use ::rpc::protos::mlx_device::{
    MlxDeviceReport as MlxDeviceReportPb, PublishMlxDeviceReportRequest,
    PublishMlxDeviceReportResponse,
};
use mlxconfig_device::report::MlxDeviceReport;
use scout::CarbideClientResult;

// create_device_report_request is a one stop shop to collect
// Mellanox device data from the machine, create a report, convert
// it into the underlying protobuf type, and then return a request
// instance to publish to carbide-api.
pub fn create_device_report_request() -> Result<PublishMlxDeviceReportRequest, String> {
    tracing::info!("creating PublishMlxDeviceReportRequest");
    let report = MlxDeviceReport::new().collect()?;
    let report_pb: MlxDeviceReportPb = report.into();
    Ok(PublishMlxDeviceReportRequest {
        report: Some(report_pb),
    })
}

// publish_mlx_device_report is used to publish an MlxDeviceReport for the current
// machine, which will collect the hardware + firmware/version details of all Mellanox
// devices on the machine, including DPUs and DPAs. This is then published to carbide-api,
// which leverages this data for ensuring devices are synced with the correct mlxconfig
// settings, and have been (or will be instructed to) updated to the correct firmware version.
//
// When called from scout on a host, a report will contain *all* Mellanox devices on the host.
// When called from the agent on a DPU, a report will contain *only* the DPU its being called from.
pub async fn publish_mlx_device_report(
    config: &Options,
    req: PublishMlxDeviceReportRequest,
) -> CarbideClientResult<PublishMlxDeviceReportResponse> {
    tracing::info!("sending PublishMlxDeviceReportRequest: {req:?}");
    let request = tonic::Request::new(req);
    let mut client = client::create_forge_client(config).await?;
    let response = client
        .publish_mlx_device_report(request)
        .await?
        .into_inner();
    Ok(response)
}
