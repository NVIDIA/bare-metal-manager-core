/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use procfs::Meminfo;
use regex::Regex;
use rlimit::Resource;
use scout::CarbideClientError;
use serde::Deserialize;
use uname::uname;

use crate::deprovision::cmdrun;
use crate::CarbideClientResult;
use crate::IN_QEMU_VM;

fn check_memory_overwrite_efi_var() -> Result<(), CarbideClientError> {
    let name = match efivar::efi::VariableName::from_str(
        "MemoryOverwriteRequestControl-e20939be-32d4-41be-a150-897f85d49829",
    ) {
        Ok(o) => o,
        Err(e) => {
            return Err(CarbideClientError::GenericError(format!(
                "Can not build EFI variable name: {}",
                e
            )))
        }
    };
    let s = efivar::system();
    let mut buffer = [0u8; 1];
    match s.read(&name, &mut buffer) {
        Ok(o) => {
            if o.0 == 1 && buffer[0] == 1 {
                return Ok(());
            }
            Err(CarbideClientError::GenericError(format!(
                "Invalid result when reading MemoryOverwriteRequestControl efivar size={} value={}",
                o.0, buffer[0]
            )))
        }
        Err(e) => Err(CarbideClientError::GenericError(format!(
            "Failed to read MemoryOverwriteRequestControl efivar: {}",
            e
        ))),
    }
}

static NVME_CLI_PROG: &str = "/usr/sbin/nvme";

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

fn get_nvme_params(nvmename: &String) -> Result<NvmeParams, CarbideClientError> {
    let nvme_params_lines =
        cmdrun::run_prog(format!("{} id-ctrl {} -o json", NVME_CLI_PROG, nvmename))?;
    let nvme_drive_params = match serde_json::from_str(&nvme_params_lines) {
        Ok(o) => o,
        Err(e) => {
            return Err(CarbideClientError::GenericError(format!(
                "nvme id-ctrl parse error: {}",
                e
            )))
        }
    };
    Ok(nvme_drive_params)
}

fn clean_this_nvme(nvmename: &String) -> Result<(), CarbideClientError> {
    log::debug!("cleaning {}", nvmename);

    let nvme_drive_params = get_nvme_params(nvmename)?;

    let namespaces_supported = nvme_drive_params.oacs & 0x8 == 0x8;

    log::debug!(
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

    // list all namespaces
    let nvmens_output = cmdrun::run_prog(format!("{} list-ns {} -a", NVME_CLI_PROG, nvmename))?;

    // iterate over namespaces
    for nsline in nvmens_output.lines() {
        let caps = match NVME_NS_RE.captures(nsline) {
            Some(o) => o,
            None => continue,
        };
        let nsid = caps.get(1).map_or("", |m| m.as_str());
        log::debug!("namespace {}", nsid);

        // format with "-s2" is secure erase
        match cmdrun::run_prog(format!(
            "{} format {} -s2 -f -n {}",
            NVME_CLI_PROG, nvmename, nsid
        )) {
            Ok(_) => (),
            Err(e) => {
                if namespaces_supported {
                    // format can fail if there is a wrong params for namespace. We delete it anyway.
                    log::debug!("nvme format error: {}", e);
                } else {
                    return Err(e);
                }
            }
        }
        if namespaces_supported {
            // delete namespace
            cmdrun::run_prog(format!(
                "{} delete-ns {} -n {}",
                NVME_CLI_PROG, nvmename, nsid
            ))?;
        }
    }

    if namespaces_supported {
        let sectors = nvme_drive_params.tnvmcap / 512;
        // creating new namespace with all available sectors
        log::debug!("Creating namespace on {}", nvmename);
        let line_created_ns_id = cmdrun::run_prog(format!(
            "{} create-ns {} --nsze={} --ncap={} --flbas 0 --dps=0",
            NVME_CLI_PROG, nvmename, sectors, sectors
        ))?;
        let nsid = match NVME_NSID_RE.captures(&line_created_ns_id) {
            Some(o) => o.get(1).map_or("", |m| m.as_str()),
            None => {
                return Err(CarbideClientError::GenericError(format!(
                    "nvme cant get nsid after create-ns {}",
                    line_created_ns_id
                )))
            }
        };
        // attaching namespace to controller
        cmdrun::run_prog(format!(
            "{} attach-ns {} -n {} -c {}",
            NVME_CLI_PROG, nvmename, nsid, nvme_drive_params.cntlid
        ))?;
    }
    log::debug!("Cleanup completed for nvme device {}", nvmename);
    Ok(())
}

fn all_nvme_cleanup() -> Result<(), CarbideClientError> {
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
                match clean_this_nvme(&nvmename) {
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

#[derive(Debug)]
struct StructOsMemInfo {
    mem_total: u64,
    mem_free: u64,
    mem_available: u64,
    mem_buffers: u64,
    mem_cached: u64,
}

fn get_os_mem_info() -> Result<StructOsMemInfo, CarbideClientError> {
    let mut meminfo = StructOsMemInfo {
        mem_total: 0,
        mem_free: 0,
        mem_available: 0,
        mem_buffers: 0,
        mem_cached: 0,
    };

    let rust_meminfo = match Meminfo::new() {
        Err(e) => {
            return Err(CarbideClientError::GenericError(format!(
                "Failed to retrieve memory information: {}",
                e
            )))
        }
        Ok(o) => o,
    };
    meminfo.mem_available = match rust_meminfo.mem_available {
        None => {
            return Err(CarbideClientError::GenericError(
                "mem_available is not available".to_string(),
            ))
        }
        Some(s) => s,
    };
    meminfo.mem_total = rust_meminfo.mem_total;
    meminfo.mem_free = rust_meminfo.mem_free;
    meminfo.mem_buffers = rust_meminfo.buffers;
    meminfo.mem_cached = rust_meminfo.cached;
    log::debug!("{:?}", meminfo);
    Ok(meminfo)
}

fn memclr(msize: u64) -> i64 {
    // Allocate all available memory and fill it with 1

    let orig_brk = unsafe { libc::sbrk(0) };
    let new_brk = unsafe { orig_brk.offset(msize as isize) };

    if unsafe { libc::brk(new_brk) } != 0 {
        println!("brk set to new error");
        return -1;
    }
    unsafe {
        libc::memset(orig_brk, 1, msize as usize);
    }
    if unsafe { libc::brk(orig_brk) } != 0 {
        println!("brk set to orig error");
    }

    println!(
        "memclr done: size={} orig_brk={:?} new_brk={:?} ",
        msize, orig_brk, new_brk
    );

    0
}

fn cleanup_ram() -> Result<(), CarbideClientError> {
    if let Err(e) = Resource::AS.set(libc::RLIM_INFINITY, libc::RLIM_INFINITY) {
        return Err(CarbideClientError::GenericError(format!(
            "Failed to set rlimit: {}",
            e
        )));
    }

    let meminfo = get_os_mem_info()?;

    log::debug!(
        "Preparing to cleanup {} bytes of RAM",
        meminfo.mem_available
    );
    let mut mem_clr_res: i64;

    mem_clr_res = memclr(meminfo.mem_available);
    let meminfo2 = get_os_mem_info()?;

    if mem_clr_res != 0 {
        return Err(CarbideClientError::GenericError(format!(
            "Mem cleanup failed with code {}",
            mem_clr_res
        )));
    }

    if meminfo.mem_free >= meminfo2.mem_free {
        return Err(CarbideClientError::GenericError(
            format!("Incomplete memory cleanup. Memory free before cleanup: {}. Memory free after cleanup: {}.",
            meminfo.mem_free,
            meminfo2.mem_free
        )));
    }

    mem_clr_res = memclr(meminfo2.mem_available);
    if mem_clr_res != 0 {
        return Err(CarbideClientError::GenericError(format!(
            "Mem cleanup 2 failed with code {}",
            mem_clr_res
        )));
    }

    Ok(())
}

async fn do_cleanup(machine_id: &str) -> CarbideClientResult<rpc::MachineCleanupInfo> {
    let mut cleanup_result = rpc::MachineCleanupInfo {
        machine_id: Some(machine_id.to_string().into()),
        nvme: None,
        ram: None,
        mem_overwrite: None,
        result: rpc::machine_cleanup_info::CleanupResult::Ok as _,
    };

    // do nvme cleanup only if stdin is /dev/null. This is because we afraid to cleanum someone's nvme drive.
    let stdin_link = match fs::read_link("/proc/self/fd/0") {
        Ok(o) => o.to_string_lossy().to_string(),
        Err(_) => "None".to_string(),
    };

    if stdin_link == "/dev/null" {
        match all_nvme_cleanup() {
            Ok(_) => {
                cleanup_result.nvme = Some(rpc::machine_cleanup_info::CleanupStepResult {
                    result: rpc::machine_cleanup_info::CleanupResult::Ok as _,
                    message: "OK".to_string(),
                });
            }
            Err(e) => {
                log::error!("{}", e);
                cleanup_result.nvme = Some(rpc::machine_cleanup_info::CleanupStepResult {
                    result: rpc::machine_cleanup_info::CleanupResult::Error as _,
                    message: e.to_string(),
                });
                cleanup_result.result = rpc::machine_cleanup_info::CleanupResult::Error as _;
            }
        }
    } else {
        log::info!("stdin == {}. Skip nvme cleanup.", stdin_link);
    }

    match check_memory_overwrite_efi_var() {
        Ok(_) => {
            cleanup_result.mem_overwrite = Some(rpc::machine_cleanup_info::CleanupStepResult {
                result: rpc::machine_cleanup_info::CleanupResult::Ok as _,
                message: "OK".to_string(),
            });
        }
        Err(e) => {
            log::error!("{}", e);
            cleanup_result.mem_overwrite = Some(rpc::machine_cleanup_info::CleanupStepResult {
                result: rpc::machine_cleanup_info::CleanupResult::Error as _,
                message: e.to_string(),
            });
            if !IN_QEMU_VM.read().await.in_qemu {
                cleanup_result.result = rpc::machine_cleanup_info::CleanupResult::Error as _;
            }
        }
    }

    match cleanup_ram() {
        Ok(_) => {
            cleanup_result.ram = Some(rpc::machine_cleanup_info::CleanupStepResult {
                result: rpc::machine_cleanup_info::CleanupResult::Ok as _,
                message: "OK".to_string(),
            });
        }
        Err(e) => {
            log::error!("{}", e);
            cleanup_result.ram = Some(rpc::machine_cleanup_info::CleanupStepResult {
                result: rpc::machine_cleanup_info::CleanupResult::Error as _,
                message: e.to_string(),
            });
            cleanup_result.result = rpc::machine_cleanup_info::CleanupResult::Error as _;
        }
    }

    Ok(cleanup_result)
}

fn is_host() -> bool {
    // this is temporary fix. We should not run scrabbing on DPU.
    // we need cleanup only on x86_64
    match uname().map_err(|_| true) {
        Ok(info) => match info.machine.as_str() {
            "x86_64" => return true,
            arch => {
                log::debug!("We do not need cleanup for DPU machine. Arch is {}", arch);
                return false;
            }
        },
        Err(e) => log::error!("uname error: {}", e),
    }
    true
}

pub async fn run(api: &str, machine_id: &str) -> CarbideClientResult<()> {
    log::info!("full deprovision starts.");
    if !is_host() {
        // do not send API cleanup_machine_completed
        return Ok(());
    }
    let info = do_cleanup(machine_id).await?;
    let mut client = rpc::forge_client::ForgeClient::connect(api.to_string()).await?;
    let request = tonic::Request::new(info);
    client.cleanup_machine_completed(request).await?;
    Ok(())
}

pub fn run_no_api() {
    log::info!("no_api deprovision starts.");
    let stdin_link = match fs::read_link("/proc/self/fd/0") {
        Ok(o) => o.to_string_lossy().to_string(),
        Err(_) => "None".to_string(),
    };
    log::info!("stdin is {}", stdin_link);

    if stdin_link == "/dev/null" {
        match all_nvme_cleanup() {
            Ok(_) => log::debug!("nvme cleanup OK"),
            Err(e) => log::error!("nvme cleanup error: {}", e),
        }
    } else {
        log::info!("stdin == {}. Skip nvme cleanup.", stdin_link);
    }
}
