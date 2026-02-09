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
use std::fs;
use std::str::FromStr;

use ::rpc::forge as rpc;
use carbide_host_support::hardware_enumeration::discovery_ibs;
use carbide_uuid::machine::MachineId;
use regex::Regex;
use scout::CarbideClientError;
use serde::Deserialize;
use smbioslib::SMBiosSystemInformation;
use tracing::Instrument;

use crate::cfg::Options;
use crate::client::create_forge_client;
use crate::deprovision::cmdrun;
use crate::{CarbideClientResult, IN_QEMU_VM};

fn check_memory_overwrite_efi_var() -> Result<(), CarbideClientError> {
    let name = match efivar::efi::Variable::from_str(
        "MemoryOverwriteRequestControl-e20939be-32d4-41be-a150-897f85d49829",
    ) {
        Ok(o) => o,
        Err(e) => {
            return Err(CarbideClientError::GenericError(format!(
                "Can not build EFI variable name: {e}"
            )));
        }
    };
    let s = efivar::system();
    match s.read(&name) {
        Ok((buffer, _)) => {
            if buffer.len() == 1 && buffer[0] == 1 {
                return Ok(());
            }
            Err(CarbideClientError::GenericError(format!(
                "Invalid result when reading MemoryOverwriteRequestControl efivar size={} value={}",
                buffer.len(),
                buffer[0]
            )))
        }
        Err(e) => Err(CarbideClientError::GenericError(format!(
            "Failed to read MemoryOverwriteRequestControl efivar: {e}"
        ))),
    }
}

static NVME_CLI_PROG: &str = "/usr/sbin/nvme";
static LENOVO_NVMI_CLI_PROG: &str = "/opt/forge/mnv_cli";

lazy_static::lazy_static! {
    static ref NVME_NS_RE: Regex = Regex::new(r".*:(0x[0-9]+)").unwrap();
    static ref NVME_NSID_RE: Regex = Regex::new(r".*nsid:([0-9]+)").unwrap();
    static ref NVME_DEV_RE: Regex = Regex::new(r"/dev/nvme[0-9]+$").unwrap();
}

#[derive(Deserialize, Debug)]
struct NvmeParams {
    // size of NVME drive in bytes
    tnvmcap: u64,

    // controller ID
    cntlid: u64,

    // Optional Admin Command Support (OACS)
    oacs: u64,

    // serial number
    sn: String,

    // manufacturer
    mn: String,

    // firmware version
    fr: String,
}

#[derive(Deserialize, Debug)]
struct NvmeLbaFormat {
    // metadata size
    ms: u16,

    // data size (as power of 2, e.g., 9 = 512B, 12 = 4096B)
    ds: u8,

    // relative performance
    rp: u8,
}

#[derive(Deserialize, Debug)]
struct NvmeNamespaceParams {
    // LBA formats array
    lbafs: Vec<NvmeLbaFormat>,
}

async fn get_nvme_params(nvmename: &str) -> Result<NvmeParams, CarbideClientError> {
    let nvme_params_lines =
        cmdrun::run_prog(NVME_CLI_PROG, ["id-ctrl", nvmename, "-o", "json"]).await?;
    let nvme_drive_params = match serde_json::from_str(&nvme_params_lines) {
        Ok(o) => o,
        Err(e) => {
            return Err(CarbideClientError::GenericError(format!(
                "nvme id-ctrl parse error: {e}"
            )));
        }
    };
    Ok(nvme_drive_params)
}

/// Select the best LBA format with the given data size (ds).
/// Prefers formats with no metadata (ms=0) and best performance (lowest rp).
/// Returns the index and a reference to the selected format, or None if not found.
fn select_best_lba_format(
    lbafs: &[NvmeLbaFormat],
    target_ds: u8,
) -> Option<(usize, &NvmeLbaFormat)> {
    lbafs
        .iter()
        .enumerate()
        .filter(|(_, lbaf)| lbaf.ds == target_ds)
        .reduce(|(best_idx, best_lbaf), (idx, lbaf)| {
            // Prefer formats with no metadata
            if lbaf.ms == 0 && best_lbaf.ms != 0
                // If metadata is same, prefer better performance (lower rp)
                || lbaf.ms == best_lbaf.ms && lbaf.rp < best_lbaf.rp
            {
                (idx, lbaf)
            } else {
                (best_idx, best_lbaf)
            }
        })
}

/// Get namespace parameters by running nvme id-ns command.
async fn get_namespace_params(nvmename: &str) -> Result<NvmeNamespaceParams, CarbideClientError> {
    let namespace_params_lines = cmdrun::run_prog(
        NVME_CLI_PROG,
        ["id-ns", nvmename, "-n", "0xffffffff", "-o", "json"],
    )
    .await?;

    let namespace_params: NvmeNamespaceParams = match serde_json::from_str(&namespace_params_lines)
    {
        Ok(o) => o,
        Err(e) => {
            return Err(CarbideClientError::GenericError(format!(
                "nvme id-ns parse error: {e}"
            )));
        }
    };

    Ok(namespace_params)
}

/// Get the best available LBA format for the given device.
/// Prefers 512B sectors (ds=9) with no metadata and best performance.
/// Falls back to 4K sectors (ds=12) if no 512B format is available.
/// If neither is found, falls back to FLBAS 0.
async fn get_best_lba_format(nvmename: &str) -> Result<(u8, u64), CarbideClientError> {
    let namespace_params = get_namespace_params(nvmename).await?;

    // Try 512B format first (ds=9 means 2^9 = 512 bytes)
    if let Some((idx, lbaf)) = select_best_lba_format(&namespace_params.lbafs, 9) {
        tracing::info!(
            "Selected FLBAS {} for {} with sector_size=512 bytes (ms={}, rp={})",
            idx,
            nvmename,
            lbaf.ms,
            lbaf.rp
        );
        return Ok((idx as u8, 512u64));
    }

    // Try 4K format (ds=12 means 2^12 = 4096 bytes)
    if let Some((idx, lbaf)) = select_best_lba_format(&namespace_params.lbafs, 12) {
        tracing::info!(
            "Selected FLBAS {} for {} with sector_size=4096 bytes (ms={}, rp={})",
            idx,
            nvmename,
            lbaf.ms,
            lbaf.rp
        );
        return Ok((idx as u8, 4096u64));
    }

    // Fallback to FLBAS 0 - determine its actual sector size
    tracing::warn!(
        "No 512B or 4K LBA format found for {}, falling back to FLBAS 0",
        nvmename
    );
    if let Some(lbaf0) = namespace_params.lbafs.first() {
        let sector_size = 1u64 << lbaf0.ds;
        tracing::warn!(
            "FLBAS 0 has sector_size={} bytes (ds={})",
            sector_size,
            lbaf0.ds
        );
        Ok((0u8, sector_size))
    } else {
        Err(CarbideClientError::GenericError(
            "No LBA formats available for device".to_string(),
        ))
    }
}

async fn clean_this_nvme(nvmename: &String) -> Result<(), CarbideClientError> {
    tracing::debug!("cleaning {}", nvmename);

    let nvme_drive_params = get_nvme_params(nvmename).await?;

    let namespaces_supported = nvme_drive_params.oacs & 0x8 == 0x8;

    tracing::debug!(
        "nvme: device={} size={} cntlid={} oacs={} namespaces_supported={} sn={} mn={} fr={}",
        nvmename,
        nvme_drive_params.tnvmcap,
        nvme_drive_params.cntlid,
        nvme_drive_params.oacs,
        namespaces_supported,
        nvme_drive_params.sn,
        nvme_drive_params.mn,
        nvme_drive_params.fr
    );

    if nvme_drive_params.mn.trim() == "M.2 NVMe 2-Bay RAID Kit" {
        let vd_out =
            cmdrun::run_prog(LENOVO_NVMI_CLI_PROG, ["info", "-o", "vd", "-i", "0"]).await?;

        // Some of the legacy raid kits were built with raid1. We need to remove the raid1
        // and the raid kit will replace it with two raid0's next reboot.
        if vd_out.contains("RAID1") {
            cmdrun::run_prog(LENOVO_NVMI_CLI_PROG, ["vd", "-a", "delete", "-i", "0"]).await?;
        } else if vd_out.contains("RAID0") {
            // assume it is two raid 0s created by the RAID kit if we see a single raid0 output
            cmdrun::run_prog(LENOVO_NVMI_CLI_PROG, ["vd", "-a", "delete", "-i", "0"]).await?;
            cmdrun::run_prog(LENOVO_NVMI_CLI_PROG, ["vd", "-a", "delete", "-i", "1"]).await?;
        } else {
            return Err(CarbideClientError::GenericError(
                "Could not find a RAID0 or RAID1 on the raid kit".to_string(),
            ));
        }

        // Clean the disks
        cmdrun::run_prog(
            LENOVO_NVMI_CLI_PROG,
            [
                "passthru",
                "-i",
                "0",
                "-o",
                "0x80",
                "-n",
                "0xffffffff",
                "--cdw10=0x200",
                "-r",
                "none",
            ],
        )
        .await?;
        cmdrun::run_prog(
            LENOVO_NVMI_CLI_PROG,
            [
                "passthru",
                "-i",
                "1",
                "-o",
                "0x80",
                "-n",
                "0xffffffff",
                "--cdw10=0x200",
                "-r",
                "none",
            ],
        )
        .await?;
    } else {
        // list all namespaces
        let nvmens_output = cmdrun::run_prog(NVME_CLI_PROG, ["list-ns", nvmename, "-a"]).await?;

        // iterate over namespaces
        for nsline in nvmens_output.lines() {
            let caps = match NVME_NS_RE.captures(nsline) {
                Some(o) => o,
                None => continue,
            };
            let nsid = caps.get(1).map_or("", |m| m.as_str());
            tracing::debug!("namespace {}", nsid);

            // format with "-s2" is secure erase
            match cmdrun::run_prog(NVME_CLI_PROG, ["format", nvmename, "-s2", "-f", "-n", nsid])
                .await
            {
                Ok(_) => (),
                Err(e) => {
                    if namespaces_supported {
                        // format can fail if there is a wrong params for namespace. We delete it anyway.
                        tracing::debug!("nvme format error: {}", e);
                    } else {
                        return Err(e);
                    }
                }
            }
            if namespaces_supported {
                // delete namespace
                cmdrun::run_prog(NVME_CLI_PROG, ["delete-ns", nvmename, "-n", nsid]).await?;
            }
        }

        if namespaces_supported {
            let (flbas_index, sector_size) = get_best_lba_format(nvmename).await?;
            let sectors = nvme_drive_params.tnvmcap / sector_size;
            let flbas_str = flbas_index.to_string();

            tracing::debug!(
                "Creating namespace on {} with flbas={}, sector_size={}, sectors={}",
                nvmename,
                flbas_index,
                sector_size,
                sectors
            );

            let line_created_ns_id = cmdrun::run_prog(
                NVME_CLI_PROG,
                [
                    "create-ns",
                    nvmename,
                    &format!("--nsze={sectors}"),
                    &format!("--ncap={sectors}"),
                    "--flbas",
                    &flbas_str,
                    "--dps=0",
                ],
            )
            .await?;
            let nsid = match NVME_NSID_RE.captures(&line_created_ns_id) {
                Some(o) => o.get(1).map_or("", |m| m.as_str()),
                None => {
                    return Err(CarbideClientError::GenericError(format!(
                        "nvme cant get nsid after create-ns {line_created_ns_id}"
                    )));
                }
            };
            // attaching namespace to controller
            cmdrun::run_prog(
                NVME_CLI_PROG,
                [
                    "attach-ns",
                    nvmename,
                    "-n",
                    nsid,
                    "-c",
                    &nvme_drive_params.cntlid.to_string(),
                ],
            )
            .await?;
        }
    }
    tracing::debug!("Cleanup completed for nvme device {}", nvmename);
    Ok(())
}

/// Failed NVMe device cleanup with error context
struct CleanupFailure {
    device: String,
    duration: std::time::Duration,
    error: CarbideClientError,
}

async fn all_nvme_cleanup() -> Result<(), CarbideClientError> {
    let mut nvme_devicepaths: Vec<String> = Vec::new();
    if let Ok(paths) = fs::read_dir("/dev") {
        for entry in paths {
            let path = match entry {
                Ok(o) => o.path(),
                Err(_) => continue,
            };
            if path.is_dir() {
                continue;
            }

            let nvmename = path.to_string_lossy().to_string();
            if NVME_DEV_RE.is_match(&nvmename) {
                nvme_devicepaths.push(nvmename);
            }
        }
    }

    let device_count = nvme_devicepaths.len();
    if device_count == 0 {
        tracing::info!("No NVMe devices found to clean");
        return Ok(());
    }

    tracing::info!(device_count, "Starting NVMe cleanup");
    let start_time = std::time::Instant::now();

    // Spawn async tasks for each NVMe device cleanup
    let cleanup_futures: Vec<_> = nvme_devicepaths
        .into_iter()
        .map(|nvmename| {
            let device = nvmename.clone();
            let span = tracing::info_span!("nvme_cleanup", device = %nvmename);

            tokio::spawn(
                async move {
                    let device_start = std::time::Instant::now();

                    tracing::info!("Starting cleanup");
                    let result = clean_this_nvme(&nvmename).await;
                    let duration = device_start.elapsed();

                    match result {
                        Ok(()) => {
                            tracing::info!(?duration, "Cleanup completed successfully");
                            Ok(())
                        }
                        Err(error) => {
                            tracing::error!(?duration, %error, "Cleanup failed");
                            Err(CleanupFailure {
                                device,
                                duration,
                                error,
                            })
                        }
                    }
                }
                .instrument(span),
            )
        })
        .collect();

    // Wait for all cleanup tasks to complete
    let results = futures_util::future::join_all(cleanup_futures).await;
    let total_duration = start_time.elapsed();

    // Collect and categorize results
    let mut errors: Vec<String> = Vec::new();
    let mut success_count = 0;

    for join_result in results {
        let cleanup_result = join_result.expect("nvme cleanup task panicked");
        match cleanup_result {
            Ok(()) => success_count += 1,
            Err(failure) => errors.push(format!(
                "NVME_CLEAN_ERROR (device: {}; duration: {:?}): {}",
                failure.device, failure.duration, failure.error,
            )),
        }
    }

    tracing::info!(
        device_count,
        success_count,
        error_count = errors.len(),
        ?total_duration,
        "NVMe cleanup completed"
    );

    if !errors.is_empty() {
        return Err(CarbideClientError::GenericError(errors.join("\n")));
    }

    Ok(())
}

// #[derive(Debug)]
// struct StructOsMemInfo {
//     mem_total: u64,
//     mem_free: u64,
//     mem_available: u64,
//     mem_buffers: u64,
//     mem_cached: u64,
// }

// fn get_os_mem_info() -> Result<StructOsMemInfo, CarbideClientError> {
//     let mut meminfo = StructOsMemInfo {
//         mem_total: 0,
//         mem_free: 0,
//         mem_available: 0,
//         mem_buffers: 0,
//         mem_cached: 0,
//     };

//     let rust_meminfo = match Meminfo::new() {
//         Err(e) => {
//             return Err(CarbideClientError::GenericError(format!(
//                 "Failed to retrieve memory information: {}",
//                 e
//             )))
//         }
//         Ok(o) => o,
//     };
//     meminfo.mem_available = match rust_meminfo.mem_available {
//         None => {
//             return Err(CarbideClientError::GenericError(
//                 "mem_available is not available".to_string(),
//             ))
//         }
//         Some(s) => s,
//     };
//     meminfo.mem_total = rust_meminfo.mem_total;
//     meminfo.mem_free = rust_meminfo.mem_free;
//     meminfo.mem_buffers = rust_meminfo.buffers;
//     meminfo.mem_cached = rust_meminfo.cached;
//     tracing::debug!("{:?}", meminfo);
//     Ok(meminfo)
// }

// fn memclr(msize: u64) -> i64 {
//     // Allocate all available memory and fill it with 1

//     let orig_brk = unsafe { libc::sbrk(0) };
//     let new_brk = unsafe { orig_brk.offset(msize as isize) };

//     if unsafe { libc::brk(new_brk) } != 0 {
//         println!("brk set to new error");
//         return -1;
//     }
//     unsafe {
//         libc::memset(orig_brk, 1, msize as usize);
//     }
//     if unsafe { libc::brk(orig_brk) } != 0 {
//         println!("brk set to orig error");
//     }

//     println!(
//         "memclr done: size={} orig_brk={:?} new_brk={:?} ",
//         msize, orig_brk, new_brk
//     );

//     0
// }

// fn cleanup_ram() -> Result<(), CarbideClientError> {
//     if let Err(e) = Resource::AS.set(libc::RLIM_INFINITY, libc::RLIM_INFINITY) {
//         return Err(CarbideClientError::GenericError(format!(
//             "Failed to set rlimit: {}",
//             e
//         )));
//     }

//     let meminfo = get_os_mem_info()?;

//     tracing::debug!(
//         "Preparing to cleanup {} bytes of RAM",
//         meminfo.mem_available
//     );
//     let mut mem_clr_res: i64;

//     mem_clr_res = memclr(meminfo.mem_available);
//     let meminfo2 = get_os_mem_info()?;

//     if mem_clr_res != 0 {
//         return Err(CarbideClientError::GenericError(format!(
//             "Mem cleanup failed with code {}",
//             mem_clr_res
//         )));
//     }

//     if meminfo.mem_free >= meminfo2.mem_free {
//         return Err(CarbideClientError::GenericError(
//             format!("Incomplete memory cleanup. Memory free before cleanup: {}. Memory free after cleanup: {}.",
//             meminfo.mem_free,
//             meminfo2.mem_free
//         )));
//     }

//     mem_clr_res = memclr(meminfo2.mem_available);
//     if mem_clr_res != 0 {
//         return Err(CarbideClientError::GenericError(format!(
//             "Mem cleanup 2 failed with code {}",
//             mem_clr_res
//         )));
//     }

//     Ok(())
// }

// Set KEEP_IB_LINK_UP on all non-DPU IB devices.
// This ensures the port link state remains up independent of host OS,
// making the port visible to UFM regardless of driver state.
// Sets P1 (required) and P2 (optional, for dual-port devices).
async fn set_ib_link_up() -> Result<(), CarbideClientError> {
    match discovery_ibs() {
        Ok(ibs) => {
            for ib in ibs {
                if let Some(p) = ib.pci_properties {
                    let slot = p.slot.unwrap();
                    // Set P1 (required - all IB devices have P1)
                    match cmdrun::run_prog(
                        "mstconfig",
                        ["-y", "-d", &slot, "set", "KEEP_IB_LINK_UP_P1=1"],
                    )
                    .await
                    {
                        Ok(_) => {
                            tracing::info!(
                                "set KEEP_IB_LINK_UP_P1=1 on IB device {} successfully.",
                                slot
                            );
                        }
                        Err(e) => {
                            tracing::error!("{}", e);
                            return Err(e);
                        }
                    }
                    // Set P2 (optional - only dual-port devices have P2)
                    match cmdrun::run_prog(
                        "mstconfig",
                        ["-y", "-d", &slot, "set", "KEEP_IB_LINK_UP_P2=1"],
                    )
                    .await
                    {
                        Ok(_) => {
                            tracing::info!(
                                "set KEEP_IB_LINK_UP_P2=1 on IB device {} successfully.",
                                slot
                            );
                        }
                        Err(e) => {
                            // P2 may not exist on single-port devices, ignore error
                            tracing::debug!(
                                "KEEP_IB_LINK_UP_P2 not available on IB device {} (single-port): {}",
                                slot,
                                e
                            );
                        }
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!("{}", e);
            return Err(CarbideClientError::GenericError(format!(
                "Failed to get ibs: {e}"
            )));
        }
    }

    Ok(())
}

// reuse hardware_enumeration::discovery_ibs to get all the non-DPU devices.
// in forge case, all the non-DPU device should be VPI device or IB-only device
// `reset` will set the link_type to IB for all the devices.
// It calls set_ib_link_up() to set KEEP_IB_LINK_UP for P1/P2 which is now default state.
async fn reset_ib_devices() -> Result<(), CarbideClientError> {
    match discovery_ibs() {
        Ok(ibs) => {
            for ib in ibs {
                if let Some(p) = ib.pci_properties {
                    let slot = p.slot.unwrap();
                    match cmdrun::run_prog("mstconfig", ["-y", "-d", &slot, "reset"]).await {
                        Ok(_) => {
                            tracing::info!("reset IB device {} successfully.", slot);
                        }
                        Err(e) => {
                            tracing::error!("{}", e);
                            return Err(e);
                        }
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!("{}", e);
            return Err(CarbideClientError::GenericError(format!(
                "Failed to get ibs: {e}"
            )));
        }
    }

    set_ib_link_up().await
}

async fn do_cleanup(machine_id: &MachineId) -> CarbideClientResult<rpc::MachineCleanupInfo> {
    let mut cleanup_result = rpc::MachineCleanupInfo {
        machine_id: Some(*machine_id),
        nvme: None,
        ram: None,
        mem_overwrite: None,
        ib: None,
        result: rpc::machine_cleanup_info::CleanupResult::Ok as _,
    };

    // do nvme cleanup only if stdin is /dev/null. This is because we afraid to cleanum someone's nvme drive.
    let stdin_link = match fs::read_link("/proc/self/fd/0") {
        Ok(o) => o.to_string_lossy().to_string(),
        Err(_) => "None".to_string(),
    };

    if stdin_link == "/dev/null" {
        match all_nvme_cleanup().await {
            Ok(_) => {
                cleanup_result.nvme = Some(rpc::machine_cleanup_info::CleanupStepResult {
                    result: rpc::machine_cleanup_info::CleanupResult::Ok as _,
                    message: "OK".to_string(),
                });
            }
            Err(e) => {
                tracing::error!("{}", e);
                cleanup_result.nvme = Some(rpc::machine_cleanup_info::CleanupStepResult {
                    result: rpc::machine_cleanup_info::CleanupResult::Error as _,
                    message: e.to_string(),
                });
                cleanup_result.result = rpc::machine_cleanup_info::CleanupResult::Error as _;
            }
        }
    } else {
        tracing::info!("stdin == {}. Skip nvme cleanup.", stdin_link);
    }

    match check_memory_overwrite_efi_var() {
        Ok(_) => {
            cleanup_result.mem_overwrite = Some(rpc::machine_cleanup_info::CleanupStepResult {
                result: rpc::machine_cleanup_info::CleanupResult::Ok as _,
                message: "OK".to_string(),
            });
        }
        Err(e) => {
            tracing::error!("{}", e);
            cleanup_result.mem_overwrite = Some(rpc::machine_cleanup_info::CleanupStepResult {
                result: rpc::machine_cleanup_info::CleanupResult::Error as _,
                message: e.to_string(),
            });
            if !IN_QEMU_VM.read().await.in_qemu {
                cleanup_result.result = rpc::machine_cleanup_info::CleanupResult::Error as _;
            }
        }
    }

    // Memory cleanup is disabled until we can guarantee the system won't run out of memory while performing it
    // match cleanup_ram() {
    //     Ok(_) => {
    //         cleanup_result.ram = Some(rpc::machine_cleanup_info::CleanupStepResult {
    //             result: rpc::machine_cleanup_info::CleanupResult::Ok as _,
    //             message: "OK".to_string(),
    //         });
    //     }
    //     Err(e) => {
    //         tracing::error!("{}", e);
    //         cleanup_result.ram = Some(rpc::machine_cleanup_info::CleanupStepResult {
    //             result: rpc::machine_cleanup_info::CleanupResult::Error as _,
    //             message: e.to_string(),
    //         });
    //         cleanup_result.result = rpc::machine_cleanup_info::CleanupResult::Error as _;
    //     }
    // }

    match reset_ib_devices().await {
        Ok(_) => {
            cleanup_result.ib = Some(rpc::machine_cleanup_info::CleanupStepResult {
                result: rpc::machine_cleanup_info::CleanupResult::Ok as _,
                message: "OK".to_string(),
            });
        }
        Err(e) => {
            tracing::error!("{}", e);
            cleanup_result.ib = Some(rpc::machine_cleanup_info::CleanupStepResult {
                result: rpc::machine_cleanup_info::CleanupResult::Error as _,
                message: e.to_string(),
            });
            cleanup_result.result = rpc::machine_cleanup_info::CleanupResult::Error as _;
        }
    }

    Ok(cleanup_result)
}

fn is_host() -> bool {
    match smbioslib::table_load_from_device() {
        Ok(data) => data.any(|sys_info: SMBiosSystemInformation| {
            !sys_info
                .product_name()
                .to_string()
                .to_lowercase()
                .contains("bluefield")
        }),
        Err(_err) => true,
    }
}

pub(crate) async fn run(config: &Options, machine_id: &MachineId) -> CarbideClientResult<()> {
    tracing::info!("full deprovision starts.");
    if !is_host() {
        tracing::info!("full deprovision skipped, we are not running on a host.");
        // do not send API cleanup_machine_completed
        return Ok(());
    }
    tracing::info!("Machine cleanup starting, we are running on a host.");
    let info = do_cleanup(machine_id).await?;
    let mut client = create_forge_client(config).await?;
    let request = tonic::Request::new(info);
    client.cleanup_machine_completed(request).await?;
    Ok(())
}

pub async fn run_no_api() -> Result<(), CarbideClientError> {
    if !is_host() {
        tracing::info!("No cleanup needed on DPU.");
        return Ok(());
    }
    tracing::info!("no_api deprovision starts.");
    let stdin_link = match fs::read_link("/proc/self/fd/0") {
        Ok(o) => o.to_string_lossy().to_string(),
        Err(_) => "None".to_string(),
    };
    tracing::info!("stdin is {}", stdin_link);

    if stdin_link == "/dev/null" {
        match all_nvme_cleanup().await {
            Ok(_) => tracing::debug!("nvme cleanup OK"),
            Err(e) => tracing::error!("nvme cleanup error: {}", e),
        }
    } else {
        tracing::info!("stdin == {}. Skip nvme cleanup.", stdin_link);
    }

    // P1 errors are propagated (fail startup), P2 errors are handled internally in reset_ib_devices()
    reset_ib_devices().await?;
    tracing::debug!("IB devices reset OK");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_namespace_params_512b_first() {
        let json = r#"{
            "lbafs": [
                {"ms": 0, "ds": 9, "rp": 0},
                {"ms": 8, "ds": 9, "rp": 1},
                {"ms": 0, "ds": 12, "rp": 0}
            ]
        }"#;

        let params: NvmeNamespaceParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.lbafs.len(), 3);
        assert_eq!(params.lbafs[0].ds, 9);
        assert_eq!(params.lbafs[0].ms, 0);
        assert_eq!(params.lbafs[2].ds, 12);
    }

    #[test]
    fn test_parse_namespace_params_4096b_first() {
        let json = r#"{
            "lbafs": [
                {"ms": 0, "ds": 12, "rp": 0},
                {"ms": 8, "ds": 12, "rp": 1},
                {"ms": 0, "ds": 9, "rp": 0}
            ]
        }"#;

        let params: NvmeNamespaceParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.lbafs.len(), 3);
        assert_eq!(params.lbafs[0].ds, 12);
        assert_eq!(params.lbafs[2].ds, 9);
    }

    #[test]
    fn test_select_best_512b_format() {
        // Test case: Multiple 512B formats, prefer ms=0 and rp=0
        let lbafs = vec![
            NvmeLbaFormat {
                ms: 8,
                ds: 9,
                rp: 1,
            },
            NvmeLbaFormat {
                ms: 0,
                ds: 9,
                rp: 0,
            },
            NvmeLbaFormat {
                ms: 0,
                ds: 12,
                rp: 0,
            },
        ];

        let best_format = select_best_lba_format(&lbafs, 9);
        assert!(best_format.is_some());
        let (idx, lbaf) = best_format.unwrap();
        assert_eq!(idx, 1); // Should select format at index 1 (ms=0, rp=0)
        assert_eq!(lbaf.ms, 0);
        assert_eq!(lbaf.rp, 0);
    }

    #[test]
    fn test_select_best_4k_format() {
        // Test case: Multiple 4K formats, prefer ms=0 and best rp
        let lbafs = vec![
            NvmeLbaFormat {
                ms: 8,
                ds: 12,
                rp: 2,
            },
            NvmeLbaFormat {
                ms: 0,
                ds: 12,
                rp: 1,
            },
            NvmeLbaFormat {
                ms: 0,
                ds: 12,
                rp: 0,
            },
        ];

        let best_format = select_best_lba_format(&lbafs, 12);
        assert!(best_format.is_some());
        let (idx, lbaf) = best_format.unwrap();
        assert_eq!(idx, 2); // Should select format at index 2 (ms=0, rp=0)
        assert_eq!(lbaf.ms, 0);
        assert_eq!(lbaf.rp, 0);
    }

    #[test]
    fn test_select_format_prefer_no_metadata() {
        // Test case: Prefer no metadata even with slightly worse performance
        let lbafs = vec![
            NvmeLbaFormat {
                ms: 8,
                ds: 9,
                rp: 0,
            },
            NvmeLbaFormat {
                ms: 0,
                ds: 9,
                rp: 1,
            },
        ];

        let best_format = select_best_lba_format(&lbafs, 9);
        assert!(best_format.is_some());
        let (idx, lbaf) = best_format.unwrap();
        assert_eq!(idx, 1); // Should prefer ms=0 even though rp is worse
        assert_eq!(lbaf.ms, 0);
    }

    #[test]
    fn test_select_format_not_found() {
        // Test case: No matching format
        let lbafs = vec![NvmeLbaFormat {
            ms: 0,
            ds: 12,
            rp: 0,
        }];

        let best_format = select_best_lba_format(&lbafs, 9);
        assert!(best_format.is_none());
    }

    #[test]
    fn test_sector_count_calculations() {
        // Test with 512B sectors
        let tnvmcap = 1_000_000_000_000u64; // 1TB
        let sector_size_512 = 512u64;
        let sectors_512 = tnvmcap / sector_size_512;
        assert_eq!(sectors_512, 1_953_125_000);

        // Test with 4096B sectors
        let sector_size_4096 = 4096u64;
        let sectors_4096 = tnvmcap / sector_size_4096;
        assert_eq!(sectors_4096, 244_140_625);

        // Verify the ratio is 8:1
        assert_eq!(sectors_512 / sectors_4096, 8);
    }

    #[test]
    fn test_lbaf_sector_size_calculation() {
        // ds=9 means 2^9 = 512 bytes
        let ds_512 = 9u8;
        let sector_size_512 = 1u64 << ds_512;
        assert_eq!(sector_size_512, 512);

        // ds=12 means 2^12 = 4096 bytes
        let ds_4096 = 12u8;
        let sector_size_4096 = 1u64 << ds_4096;
        assert_eq!(sector_size_4096, 4096);
    }
}
