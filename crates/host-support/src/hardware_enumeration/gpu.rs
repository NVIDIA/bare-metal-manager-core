/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use ::rpc::machine_discovery::Gpu as RpcGpu;
use utils::cmd::Cmd;

use super::HardwareEnumerationResult;

/// Retrieve nvidia-smi data about a machine.
///
/// It is assumed that the machine should have the nvidia kernel module loaded, or this call will fail.
pub fn get_nvidia_smi_data() -> HardwareEnumerationResult<Vec<RpcGpu>> {
    let cmd = Cmd::new("timeout")
        .args(vec![
            "--kill-after=120s",
            "60s",
            "nvidia-smi",
            "--format=csv,noheader",
            concat!(
                "--query-gpu=name,serial,driver_version,vbios_version,inforom.image,memory.total,",
                "clocks.applications.gr,pci.bus_id,platform.chassis_serial_number,platform.slot_number,",
                "platform.tray_index,platform.host_id,platform.module_id,platform.gpu_fabric_guid"
            )
        ])
        .output()?;

    let mut csv_reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .trim(csv::Trim::All)
        .from_reader(cmd.as_bytes());
    let mut gpus = Vec::default();
    for result in csv_reader.deserialize() {
        match result {
            Ok(gpu) => gpus.push(gpu),
            Err(error) => tracing::error!("Could not parse nvidia-smi output: {}", error),
        }
    }

    Ok(gpus)
}
