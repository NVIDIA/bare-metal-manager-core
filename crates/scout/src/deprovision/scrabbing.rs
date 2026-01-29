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
use std::fs;
use std::str::FromStr;

use ::rpc::forge as rpc;
use carbide_host_support::hardware_enumeration::discovery_ibs;
use carbide_uuid::machine::MachineId;
use regex::Regex;
use scout::CarbideClientError;
use serde::Deserialize;
use smbioslib::SMBiosSystemInformation;

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

async fn get_nvme_params(nvmename: &String) -> Result<NvmeParams, CarbideClientError> {
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
            let sectors = nvme_drive_params.tnvmcap / 512;
            // creating new namespace with all available sectors
            tracing::debug!("Creating namespace on {}", nvmename);
            let line_created_ns_id = cmdrun::run_prog(
                NVME_CLI_PROG,
                [
                    "create-ns",
                    nvmename,
                    &format!("--nsze={sectors}"),
                    &format!("--ncap={sectors}"),
                    "--flbas",
                    "0",
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

async fn all_nvme_cleanup() -> Result<(), CarbideClientError> {
    let mut err_vec: Vec<String> = Vec::new();

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
                match clean_this_nvme(&nvmename).await {
                    Ok(_) => (),
                    Err(e) => err_vec.push(format!("NVME_CLEAN_ERROR:{}:{}", &nvmename, e)),
                }
            }
        }
    }
    if !err_vec.is_empty() {
        return Err(CarbideClientError::GenericError(err_vec.join("\n")));
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
