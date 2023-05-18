use crate::cmd::Cmd;
use ::rpc::machine_discovery::Gpu as RpcGpu;

use super::HardwareEnumerationResult;

pub fn discover_gpus() -> HardwareEnumerationResult<Vec<RpcGpu>> {
    let cmd = Cmd::new("nvidia-smi")
        .args(vec!["--format=csv,noheader", "--query-gpu=name,serial,driver_version,vbios_version,inforom.image,memory.total,clocks.applications.gr,pci.bus_id"])
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
