use std::collections::HashMap;

use ::rpc::forge_tls_client::ApiConfig;
use prettytable::{row, Table};
use utils::admin_cli::{CarbideCliResult, OutputFormat};

use crate::cfg::carbide_options::ShowExpectedMachineQuery;
use crate::rpc;

pub async fn show_expected_machines(
    expected_machine_query: &ShowExpectedMachineQuery,
    api_config: &ApiConfig<'_>,
    output_format: OutputFormat,
) -> CarbideCliResult<()> {
    if let Some(bmc_mac_address) = expected_machine_query.bmc_mac_address {
        let expected_machine = rpc::get_expected_machine(bmc_mac_address, api_config).await?;
        println!("{:#?}", expected_machine);
        return Ok(());
    }

    let expected_machines = rpc::get_all_expected_machines(api_config).await?;
    if output_format == OutputFormat::Json {
        println!(
            "{}",
            serde_json::to_string_pretty(&expected_machines).unwrap()
        );
    }

    // TODO: This should be optimised. `find_interfaces` should accept a list of macs also and
    // return related interfaces details.
    let all_mi = rpc::get_all_machines_interfaces(api_config, None).await?;
    let expected_macs = expected_machines
        .expected_machines
        .iter()
        .map(|x| x.bmc_mac_address.clone().to_lowercase())
        .collect::<Vec<String>>();

    let expected_mi: HashMap<String, ::rpc::forge::MachineInterface> =
        HashMap::from_iter(all_mi.interfaces.iter().filter_map(|x| {
            if expected_macs.contains(&x.mac_address.to_lowercase()) {
                Some((x.mac_address.clone().to_lowercase(), x.clone()))
            } else {
                None
            }
        }));

    let bmc_ips = expected_mi
        .iter()
        .filter_map(|x| {
            let ip = x.1.address.first()?;
            Some(ip.clone())
        })
        .collect::<Vec<_>>();

    let expected_bmc_ip_vs_ids = HashMap::from_iter(
        rpc::get_machines_ids_by_bmc_ips(api_config, &bmc_ips)
            .await?
            .pairs
            .iter()
            .map(|x| {
                (
                    x.bmc_ip.clone(),
                    x.machine_id
                        .clone()
                        .map(|x| x.to_string())
                        .unwrap_or("Unlinked".to_string()),
                )
            }),
    );

    convert_and_print_into_nice_table(&expected_machines, &expected_bmc_ip_vs_ids, &expected_mi)?;

    Ok(())
}

fn convert_and_print_into_nice_table(
    expected_machines: &::rpc::forge::ExpectedMachineList,
    expected_discovered_machine_ids: &HashMap<String, String>,
    expected_discovered_machine_interfaces: &HashMap<String, ::rpc::forge::MachineInterface>,
) -> CarbideCliResult<()> {
    let mut table = Box::new(Table::new());

    table.set_titles(row![
        "Serial Number",
        "BMC Mac",
        "Interface IP",
        "Fallback DPUs",
        "Associated Machine",
        "Name",
        "Description",
        "Labels"
    ]);

    for expected_machine in &expected_machines.expected_machines {
        let machine_interface = expected_discovered_machine_interfaces
            .get(&expected_machine.bmc_mac_address.to_lowercase());
        let machine_id = expected_discovered_machine_ids
            .get(
                &machine_interface
                    .and_then(|x| x.address.first().cloned())
                    .unwrap_or("unknown".to_string()),
            )
            .cloned();

        let metadata = expected_machine.metadata.clone().unwrap_or_default();
        let labels = metadata
            .labels
            .iter()
            .map(|label| {
                let key = &label.key;
                let value = label.value.clone().unwrap_or_default();
                format!("\"{}:{}\"", key, value)
            })
            .collect::<Vec<_>>();

        table.add_row(row![
            expected_machine.chassis_serial_number,
            expected_machine.bmc_mac_address,
            machine_interface
                .map(|x| x.address.join("\n"))
                .unwrap_or("Undiscovered".to_string()),
            expected_machine.fallback_dpu_serial_numbers.join("\n"),
            machine_id.unwrap_or("Unlinked".to_string()),
            metadata.name,
            metadata.description,
            labels.join(", ")
        ]);
    }

    table.printstd();

    Ok(())
}
