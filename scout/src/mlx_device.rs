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
use mlxconfig_lockdown::{LockStatus, LockdownManager, MlxResult};
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

// lock_device locks a device with a provided key. The device_address
// can either be a PCI address, or a /dev/mst/* path. Generally when
// going through the automation, we'll end up using whatever comes in
// via the mlx device reports, with the device info coming from
// mlxfwmanager, so if mst is running, it will probably be an mst path.
// BUT, even if mst is running, you can still provide a PCI address.
#[allow(dead_code)]
pub fn lock_device(device_address: &str, key: &str) -> MlxResult<()> {
    let manager = LockdownManager::new()?;
    manager.lock_device(device_address, key)?;
    Ok(())
}

// unlock_device unlocks a device with a provided key. See above comments
// in lock_device about the device_address argument formatting options.
#[allow(dead_code)]
pub fn unlock_device(device_address: &str, key: &str) -> MlxResult<()> {
    let manager = LockdownManager::new()?;
    manager.unlock_device(device_address, key)?;
    Ok(())
}

// device_lockdown_status returns the current lockdown status of
// a device (locked or unlocked). See above comments in lock_device
// about the device_address argument formatting options.
#[allow(dead_code)]
pub fn device_lockdown_status(device_address: &str) -> MlxResult<LockStatus> {
    let manager = LockdownManager::new()?;
    let status = manager.get_status(device_address)?;
    Ok(status)
}
