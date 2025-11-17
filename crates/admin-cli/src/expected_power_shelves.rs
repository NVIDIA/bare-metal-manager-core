use std::collections::HashMap;

use prettytable::{Table, row};
use rpc::admin_cli::{CarbideCliResult, OutputFormat};

use crate::cfg::cli_options::ShowExpectedPowerShelfQuery;
use crate::rpc::ApiClient;

pub async fn show_expected_power_shelves(
    expected_power_shelf_query: &ShowExpectedPowerShelfQuery,
    api_client: &ApiClient,
    output_format: OutputFormat,
) -> CarbideCliResult<()> {
    if let Some(bmc_mac_address) = expected_power_shelf_query.bmc_mac_address {
        let expected_power_shelf = api_client
            .0
            .get_expected_power_shelf(bmc_mac_address.to_string())
            .await?;
        println!("{:#?}", expected_power_shelf);
        return Ok(());
    }

    let expected_power_shelves = api_client.0.get_all_expected_power_shelves().await?;
    if output_format == OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&expected_power_shelves)?);
    }

    // TODO: This should be optimised. `find_interfaces` should accept a list of macs also and
    // return related interfaces details.
    let all_mi = api_client.get_all_machines_interfaces(None).await?;
    let expected_macs = expected_power_shelves
        .expected_power_shelves
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
        api_client
            .0
            .find_machine_ids_by_bmc_ips(bmc_ips)
            .await?
            .pairs
            .iter()
            .map(|x| {
                (
                    x.bmc_ip.clone(),
                    x.machine_id
                        .map(|x| x.to_string())
                        .unwrap_or("Unlinked".to_string()),
                )
            }),
    );

    convert_and_print_into_nice_table(
        &expected_power_shelves,
        &expected_bmc_ip_vs_ids,
        &expected_mi,
    )?;

    Ok(())
}

fn convert_and_print_into_nice_table(
    expected_power_shelves: &::rpc::forge::ExpectedPowerShelfList,
    expected_discovered_machine_ids: &HashMap<String, String>,
    expected_discovered_machine_interfaces: &HashMap<String, ::rpc::forge::MachineInterface>,
) -> CarbideCliResult<()> {
    let mut table = Box::new(Table::new());

    table.set_titles(row![
        "Serial Number",
        "BMC Mac",
        "Interface IP",
        "Associated Machine",
        "Name",
        "Description",
        "Labels"
    ]);

    for expected_power_shelf in &expected_power_shelves.expected_power_shelves {
        let machine_interface = expected_discovered_machine_interfaces
            .get(&expected_power_shelf.bmc_mac_address.to_lowercase());
        let machine_id = expected_discovered_machine_ids
            .get(
                &machine_interface
                    .and_then(|x| x.address.first().cloned())
                    .unwrap_or("unknown".to_string()),
            )
            .cloned();

        let metadata = expected_power_shelf.metadata.clone().unwrap_or_default();
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
            expected_power_shelf.shelf_serial_number,
            expected_power_shelf.bmc_mac_address,
            machine_interface
                .map(|x| x.address.join("\n"))
                .unwrap_or("Undiscovered".to_string()),
            machine_id.unwrap_or("Unlinked".to_string()),
            metadata.name,
            metadata.description,
            labels.join(", ")
        ]);
    }

    table.printstd();

    Ok(())
}
