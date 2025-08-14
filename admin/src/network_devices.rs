use std::fmt::Write;

use crate::cfg::cli_options::NetworkDeviceShow;
use crate::rpc::ApiClient;
use utils::admin_cli::{CarbideCliResult, OutputFormat};

pub async fn show(
    output_format: OutputFormat,
    query: NetworkDeviceShow,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let query_id: Option<String> = if query.all || query.id.is_empty() {
        None
    } else {
        Some(query.id)
    };

    let devices = api_client.get_network_device_topology(query_id).await?;

    match output_format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&devices)?),
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
                device
                    .remote_port
                    .split('=')
                    .next_back()
                    .unwrap_or_default()
            )?;
        }
        writeln!(&mut lines, "{}", "-".repeat(95))?;
    }
    writeln!(&mut lines)?;

    println!("{lines}");

    Ok(())
}
