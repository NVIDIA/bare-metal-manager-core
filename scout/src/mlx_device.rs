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

use ::rpc::protos::mlx_device::{
    MlxDeviceReport as MlxDeviceReportPb, PublishMlxDeviceReportRequest,
};
use mlxconfig_device::report::MlxDeviceReport;

// create_device_report_request is a one stop shop to collect
// Mellanox device data from the machine, create a report, convert
// it into the underlying protobuf type, and then return a request
// instance to publish to carbide-api.
pub fn create_device_report_request() -> Result<PublishMlxDeviceReportRequest, String> {
    let report = MlxDeviceReport::new().collect()?;
    let report_pb: MlxDeviceReportPb = report.into();
    Ok(PublishMlxDeviceReportRequest {
        report: Some(report_pb),
    })
}
