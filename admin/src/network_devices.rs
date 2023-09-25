use std::fmt::Write;

use crate::{
    cfg::carbide_options::{LldpShow, OutputFormat},
    CarbideCliResult, Config,
};

pub async fn show(
    output_format: OutputFormat,
    query: LldpShow,
    api_config: Config,
) -> CarbideCliResult<()> {
    let devices = crate::rpc::get_lldp_topology(query.id, api_config).await?;

    match output_format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&devices).unwrap()),
        OutputFormat::Csv => println!("Not Supported."),
        OutputFormat::AsciiTable => show_racks_info(&devices)?,
    }

    Ok(())
}

fn show_racks_info(data: &rpc::forge::LldpTopologyData) -> CarbideCliResult<()> {
    let mut lines = String::new();

    writeln!(&mut lines, "{}", "-".repeat(95))?;
    for tor in &data.network_devices {
        writeln!(&mut lines, "Network Device: {}/{}", tor.name, tor.id)?;
        writeln!(
            &mut lines,
            "Description:    {}",
            tor.description.clone().unwrap_or_default()
        )?;
        writeln!(&mut lines, "Mgmt IP:        {}", tor.mgmt_ip.join(","))?;
        writeln!(&mut lines, "Discover Via:   {}", tor.discovered_via)?;
        writeln!(&mut lines, "Device Type:    {}", tor.device_type)?;
        writeln!(&mut lines)?;
        writeln!(&mut lines, "Connected DPU(s):")?;
        for dpu in &tor.dpus {
            writeln!(
                &mut lines,
                "\t\t{} | {}",
                dpu.id.clone().unwrap_or_default(),
                dpu.local_port
            )?;
        }
        writeln!(&mut lines, "{}", "-".repeat(95))?;
    }
    writeln!(&mut lines)?;

    println!("{}", lines);

    Ok(())
}
