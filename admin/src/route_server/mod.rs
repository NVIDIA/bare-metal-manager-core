use crate::cfg::cli_options::RouteServer;
use crate::rpc::ApiClient;
use ::rpc::forge as rpc;
use prettytable::{Cell, Row, Table};
use utils::admin_cli::{CarbideCliError, CarbideCliResult, output};

// dispatch is a dispatch handler for admin CLI
// route-server subcommands.
pub async fn dispatch(
    command: &RouteServer,
    api_client: &ApiClient,
    output: output::OutputFormat,
) -> CarbideCliResult<()> {
    match command {
        RouteServer::Get => {
            let route_servers = api_client.0.get_route_servers().await?;
            match output {
                output::OutputFormat::AsciiTable => {
                    let table = route_servers_to_table(&route_servers)?;
                    table.printstd();
                }
                output::OutputFormat::Csv => {
                    println!("address,source_type");
                    for route_server in &route_servers.route_servers {
                        println!("{},{:?}", route_server.address, route_server.source_type)
                    }
                }
                output::OutputFormat::Json => {
                    println!("{}", serde_json::to_string(&route_servers)?)
                }
                output::OutputFormat::Yaml => {
                    println!("{}", serde_yaml::to_string(&route_servers)?)
                }
            }
        }
        RouteServer::Add(addresses) => {
            api_client
                .0
                .add_route_servers(rpc::RouteServers {
                    route_servers: addresses.ip.iter().map(ToString::to_string).collect(),
                    source_type: addresses.source_type as i32,
                })
                .await?
        }
        RouteServer::Remove(addresses) => {
            api_client
                .0
                .remove_route_servers(rpc::RouteServers {
                    route_servers: addresses.ip.iter().map(ToString::to_string).collect(),
                    source_type: addresses.source_type as i32,
                })
                .await?
        }
        RouteServer::Replace(addresses) => {
            api_client
                .0
                .replace_route_servers(rpc::RouteServers {
                    route_servers: addresses.ip.iter().map(ToString::to_string).collect(),
                    source_type: addresses.source_type as i32,
                })
                .await?
        }
    }
    Ok(())
}

// route_servers_to_table converts the RouteServerEntries
// response into a pretty ASCII table.
pub fn route_servers_to_table(
    route_server_entries: &rpc::RouteServerEntries,
) -> CarbideCliResult<Table> {
    let mut table = Table::new();

    // Add header row
    table.add_row(Row::new(vec![
        Cell::new("Address"),
        Cell::new("Source Type"),
    ]));

    // Add each route server as a row
    for route_server in &route_server_entries.route_servers {
        // Convert enum to string representation.
        let source_type = rpc::RouteServerSourceType::try_from(route_server.source_type)
            .map_err(|e| e.to_string())
            .map_err(CarbideCliError::GenericError)?;

        table.add_row(Row::new(vec![
            Cell::new(&route_server.address),
            Cell::new(format!("{source_type:?}").as_str()),
        ]));
    }

    Ok(table)
}
