use procfs::Meminfo;
use regex::Regex;
use rlimit::Resource;
use std::fs;

use crate::deprovision::cmdrun;
use cli::CarbideClientResult;

/*

#list namespaces:
nvme list-ns /dev/nvme0

#clear data on nvme. NS_ID namespace id:
nvme format /dev/nvme0 -n NS_ID

*/

fn clean_this_nvme(nvmename: &String) -> Result<(), String> {
    println!("cleaning {}", nvmename);
    let nvme_ns_re = match Regex::new(r"\[.*\]:(0x[0-9]+)") {
        Ok(o) => o,
        Err(e) => return Err(e.to_string()),
    };
    //test: let nvmens_output = match cmdrun::run_prog(format!("cat /tmp/nvmelisttest")){
    let nvmens_output = match cmdrun::run_prog(format!("/usr/sbin/nvme list-ns {}", nvmename)) {
        Ok(o) => o,
        Err(e) => return Err(format!("nvme list-ns error: {}", e)),
    };
    for nsline in nvmens_output.lines() {
        let caps = match nvme_ns_re.captures(nsline) {
            Some(o) => o,
            None => continue,
        };
        let nsid = caps.get(1).map_or("", |m| m.as_str());
        match cmdrun::run_prog(format!("/usr/sbin/nvme format {} -n {}", nvmename, nsid)) {
            Ok(_) => (),
            Err(e) => return Err(format!("nvme format error: {}", e)),
        }
    }
    Ok(())
}

fn all_nvme_cleanup() -> Result<(), String> {
    let nvme_re = match Regex::new(r"/dev/nvme[0-9]+$") {
        Ok(o) => o,
        Err(e) => return Err(e.to_string()),
    };

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
            if nvme_re.is_match(&nvmename) {
                match clean_this_nvme(&nvmename) {
                    Ok(_) => (),
                    Err(e) => err_vec.push(format!("NVME_CLEAN_ERROR:{}:{}", &nvmename, e)),
                }
            }
        }
    }
    if !err_vec.is_empty() {
        return Err(err_vec.join("\n"));
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

fn get_os_mem_info() -> Result<StructOsMemInfo, String> {
    let mut meminfo = StructOsMemInfo {
        mem_total: 0,
        mem_free: 0,
        mem_available: 0,
        mem_buffers: 0,
        mem_cached: 0,
    };

    let rust_meminfo = match Meminfo::new() {
        Err(e) => return Err(e.to_string()),
        Ok(o) => o,
    };
    meminfo.mem_available = match rust_meminfo.mem_available {
        None => return Err("mem_available is not available".to_string()),
        Some(s) => s,
    };
    meminfo.mem_total = rust_meminfo.mem_total;
    meminfo.mem_free = rust_meminfo.mem_free;
    meminfo.mem_buffers = rust_meminfo.buffers;
    meminfo.mem_cached = rust_meminfo.cached;
    println!("{:?}", meminfo);
    Ok(meminfo)
}

fn memclr(msize: u64) -> i64 {
    //Allocate all available memory and fill it with 1

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

fn cleanup_ram() -> Result<(), String> {
    if let Err(e) = Resource::AS.set(libc::RLIM_INFINITY, libc::RLIM_INFINITY) {
        return Err(e.to_string());
    }

    let meminfo = match get_os_mem_info() {
        Ok(o) => o,
        Err(e) => return Err(e),
    };

    println!(
        "Preparing to cleanup {} bytes of RAM",
        meminfo.mem_available
    );
    let mut mem_clr_res: i64;

    mem_clr_res = memclr(meminfo.mem_available);
    let meminfo2 = match get_os_mem_info() {
        Ok(o) => o,
        Err(e) => return Err(e),
    };

    if mem_clr_res != 0 {
        return Err("Mem cleanup failed1".to_string());
    }

    if meminfo.mem_free >= meminfo2.mem_free {
        return Err("Not complete memory cleanup.".to_string());
    }

    mem_clr_res = memclr(meminfo2.mem_available);
    if mem_clr_res != 0 {
        return Err("Mem cleanup failed2".to_string());
    }

    Ok(())
}

pub struct Deprovision {}
impl Deprovision {
    pub async fn run(_listen: String, _uuid: &str) -> CarbideClientResult<()> {
        //do nvme cleanup only if stdin is /dev/null. This is because we afraid to cleanum someone's nvme drive.
        let stdin_link = match fs::read_link("/proc/self/fd/0") {
            Ok(o) => o.to_string_lossy().to_string(),
            Err(_) => "None".to_string(),
        };

        if stdin_link == "/dev/null" {
            match all_nvme_cleanup() {
                Ok(_) => (),
                Err(e) => println!("{}", e),
            }
        } else {
            println!("stdin == {}. Skip nvme cleanup.", stdin_link);
        }
        match cleanup_ram() {
            Ok(_) => (),
            Err(e) => println!("{}", e),
        }
        Ok(())
    }
}
