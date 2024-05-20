use std::fmt::Write;

use crate::{
    cfg::carbide_options::{NetworkDeviceShow, OutputFormat},
    CarbideCliResult,
};
use ::rpc::forge_tls_client::ApiConfig;

pub async fn show(
    output_format: OutputFormat,
    query: NetworkDeviceShow,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let query_id: Option<String> = if query.all || query.id.is_empty() {
        None
    } else {
        Some(query.id)
    };

    let devices = crate::rpc::get_network_device_topology(query_id, api_config).await?;

    match output_format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&devices).unwrap()),
        OutputFormat::AsciiTable => show_network_devices_info(&devices)?,
        OutputFormat::Csv => println!("CSV not yet supported."),
        OutputFormat::Yaml => println!("YAML not yet supported."),
    }

    Ok(())
}

fn show_network_devices_info(data: &rpc::forge::NetworkTopologyData) -> CarbideCliResult<()> {
    let mut lines = String::new();

    writeln!(&mut lines, "{}", "-".repeat(95))?;
    for network_device in &data.network_devices {
        writeln!(
            &mut lines,
            "Network Device: {}/{}",
            network_device.name, network_device.id
        )?;
        writeln!(
            &mut lines,
            "Description:    {}",
            network_device.description.clone().unwrap_or_default()
        )?;
        writeln!(
            &mut lines,
            "Mgmt IP:        {}",
            network_device.mgmt_ip.join(",")
        )?;
        writeln!(
            &mut lines,
            "Discovered Via: {}",
            network_device.discovered_via
        )?;
        writeln!(&mut lines, "Device Type:    {}", network_device.device_type)?;
        writeln!(&mut lines)?;
        writeln!(&mut lines, "Connected DPU(s):")?;
        for device in &network_device.devices {
            writeln!(
                &mut lines,
                "\t\t{} | {:8} | {}",
                device.id.clone().unwrap_or_default(),
                device.local_port,
                device.remote_port.split('=').last().unwrap_or_default()
            )?;
        }
        writeln!(&mut lines, "{}", "-".repeat(95))?;
    }
    writeln!(&mut lines)?;

    println!("{}", lines);

    Ok(())
}
