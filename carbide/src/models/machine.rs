use crate::models;
use crate::protos;
use crate::{CarbideError, CarbideResult};
use log::{debug, info, warn};
use models::MachineEvent;

use std::collections::HashMap;
use std::convert::From;
use std::str;

use eui48::MacAddress;

use super::MachineAction;
use super::MachineInterface;
use super::MachineState;
use super::NetworkSegment;
use std::net::IpAddr;

#[derive(Debug)]
pub struct Machine {
    id: uuid::Uuid,
    fqdn: String,
    created: std::time::SystemTime,
    modified: std::time::SystemTime,
    events: Vec<models::MachineEvent>,
}

impl From<uuid::Uuid> for protos::Uuid {
    fn from(uuid: uuid::Uuid) -> Self {
        protos::Uuid {
            value: uuid.to_string(),
        }
    }
}

impl From<models::Machine> for protos::Machine {
    fn from(machine: models::Machine) -> Self {
        protos::Machine {
            id: Some(machine.id.into()),
            fqdn: machine.fqdn,
            created: Some(machine.created.into()),
            modified: Some(machine.modified.into()),
        }
    }
}

impl From<tokio_postgres::Row> for models::Machine {
    fn from(row: tokio_postgres::Row) -> Self {
        Self {
            id: row.get("id"),
            fqdn: row.get("fqdn"),
            created: row.get("created"),
            modified: row.get("modified"),
            events: Vec::new(),
        }
    }
}

impl From<Vec<models::Machine>> for protos::MachineList {
    fn from(machines: Vec<models::Machine>) -> Self {
        protos::MachineList {
            machines: machines.into_iter().map(protos::Machine::from).collect(),
        }
    }
}

impl Machine {
    pub async fn create(dbc: &tokio_postgres::Transaction<'_>, fqdn: String) -> CarbideResult<Self> {
        Ok(Machine::from(
            dbc.query_one(
                "INSERT INTO machines (fqdn) VALUES ($1) RETURNING *",
                &[&fqdn],
            )
            .await?,
        ))
    }

    // TODO(ajf): doesn't belong here
    pub fn generate_hostname_from_uuid(mut id: u128) -> String {
        let alpha_upper = b'A'..= b'Z';
        let alpha_lower = b'a'..= b'z';
        let numeric = b'0'..= b'9';

        let space = alpha_upper.chain(alpha_lower).chain(numeric).collect::<Vec<u8>>();

        assert_eq!(space.len(), 62);

        let mut output = Vec::with_capacity(std::mem::size_of::<u8>() * 22);
        while id > 0 {
            output.push(space[(id % 62) as usize]);
            id = id.checked_div(62).unwrap();
        }
        String::from(str::from_utf8(&output).unwrap())
    }

    pub async fn discover(
        dbc: &tokio_postgres::Transaction<'_>,
        macaddr: MacAddress,
        relay: IpAddr,
    ) -> CarbideResult<Self> {
        // Find machines that have the mac address on the subnet being relayed
        // It's possible to have duplicate mac addresses on different subnets.
        let sql = r#"
        SELECT m.* FROM
            machines m
            INNER JOIN machine_interfaces mi
                ON m.id = mi.machine_id
            INNER JOIN network_segments ns
                ON mi.segment_id = ns.id
            WHERE
                mi.mac_address = $1::macaddr
                AND
                (($2::inet <<= ns.subnet_ipv4) OR ($2::inet <<= ns.subnet_ipv6));
        "#;

        let mut results = dbc
            .query(sql, &[&macaddr, &relay])
            .await?
            .into_iter()
            .map(Machine::from)
            .collect::<Vec<Machine>>();

        assert!((0..1).contains(&results.len()));

        match results.len() {
            0 => {
                info!("No existing machine with mac address {} using network with relay: {}, creating one.", macaddr, relay);

                match NetworkSegment::for_relay(&dbc, relay).await? {
                    Some(segment) => {
                        let generated_hostname =
                            Self::generate_hostname_from_uuid(uuid::Uuid::new_v4().as_u128());
                        let generated_fqdn =
                            format!("{}.{}", generated_hostname, segment.subdomain());

                        debug!("Generated hostname {}", generated_fqdn);

                        let machine = Machine::create(&dbc, generated_fqdn).await?;

                        //
                        //let machine_interface = MachineInterface::create(&dbc, &machine, &segment, &macaddr,

                        Ok(machine)
                    }
                    None => Err(CarbideError::NoNetworkSegmentsForRelay(relay)),
                }
            }
            1 => Ok(results.remove(0)),
            _ => unreachable!(),
        }
    }

    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    pub fn created(&self) -> std::time::SystemTime {
        self.created
    }

    pub fn modified(&self) -> std::time::SystemTime {
        self.modified
    }

    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    pub fn events(&self) -> &Vec<MachineEvent> {
        &self.events
    }

    pub async fn update_fqdn(
        &mut self,
        dbc: &crate::DatabaseConnection<'_>,
        new_fqdn: &str,
    ) -> CarbideResult<&Machine> {
        let result = dbc
            .query_one(
                "UPDATE machines SET fqdn=$1 RETURNING fqdn,modified",
                &[&new_fqdn],
            )
            .await?;

        self.fqdn = result.get("fqdn");
        self.modified = result.get("modified");

        Ok(self)
    }

    pub async fn current_state(
        &self,
        dbc: &tokio_postgres::Transaction<'_>,
    ) -> CarbideResult<MachineState> {
        MachineState::for_machine(self, &dbc).await
    }

    pub async fn advance(
        &self,
        dbc: &tokio_postgres::Transaction<'_>,
        action: MachineAction,
    ) -> CarbideResult<bool> {
        let row = dbc
            .query_one(
                "INSERT INTO machine_events (machine_id, action) VALUES ($1, $2) RETURNING id",
                &[&self.id(), &action],
            )
            .await?;

        log::info!("Event ID is {}", row.get::<&str, uuid::Uuid>("id"));

        Ok(true)
    }

    pub async fn fail(&self, dbc: &tokio_postgres::Transaction<'_>) -> CarbideResult<bool> {
        self.advance(dbc, MachineAction::Fail).await
    }

    pub async fn commission(&self, dbc: &tokio_postgres::Transaction<'_>) -> CarbideResult<bool> {
        self.advance(dbc, MachineAction::Commission).await
    }

    pub async fn find(dbc: &tokio_postgres::Transaction<'_>) -> CarbideResult<Vec<Machine>> {
        // TODO(ajf): write a query langauge???

        let mut machines = dbc
            .query("SELECT * FROM machines", &[])
            .await?
            .into_iter()
            .fold(HashMap::new(), |mut accumulator, row| {
                let machine = Machine::from(row);

                accumulator.insert(machine.id, machine);

                accumulator
            })
            .into_iter()
            .collect::<HashMap<uuid::Uuid, Machine>>();

        let mut events_for_machine =
            MachineEvent::find_by_machine_ids(&dbc, machines.keys().collect()).await?;

        let hint_length = machines.len();

        let final_machine_list = machines.drain().fold(
            Vec::with_capacity(hint_length),
            move |mut accumulator, (uuid, mut machine)| {
                if let Some(events) = events_for_machine.remove(&uuid) {
                    machine.events = events;
                } else {
                    warn!("Machine {0} ({1}) has no events", machine.id, machine.fqdn);
                }
                accumulator.push(machine);
                accumulator
            },
        );

        Ok(final_machine_list)
    }
}

#[cfg(test)]
mod test {}
