use crate::{models::Machine, models::NetworkSegment, CarbideResult};
use eui48::MacAddress;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub struct MachineInterface {
    id: uuid::Uuid,

    machine_id: uuid::Uuid,
    segment_id: uuid::Uuid,

    mac_address: MacAddress,

    address_ipv4: Option<Ipv4Addr>,
    address_ipv6: Option<Ipv6Addr>,
}

impl From<tokio_postgres::Row> for MachineInterface {
    fn from(row: tokio_postgres::Row) -> Self {
        let id: uuid::Uuid = row.get("id");

        let address_ipv4 = match row.get("address_ipv4") {
            Some(IpAddr::V4(x)) => Some(Ipv4Addr::from(x)),
            Some(IpAddr::V6(_)) => panic!(
                "Found an IPv6 address in the address_ipv4 field for machine {}",
                &id
            ),
            None => None,
        };

        let address_ipv6 = match row.get("address_ipv6") {
            Some(IpAddr::V6(x)) => Some(Ipv6Addr::from(x)),
            Some(IpAddr::V4(_)) => panic!(
                "Found an IPv4 address in the address_ipv4 field for machine {}",
                &id
            ),
            None => None,
        };

        Self {
            id: row.get("id"),
            machine_id: row.get("machine_id"),
            segment_id: row.get("segment_id"),
            mac_address: row.get("mac_address"),

            address_ipv4,
            address_ipv6,
        }
    }
}

impl MachineInterface {
    pub async fn find_by_mac_address(
        dbc: &crate::DatabaseConnection<'_>,
        macaddr: MacAddress,
    ) -> CarbideResult<Vec<MachineInterface>> {
        Ok(dbc
            .query(
                "SELECT * FROM machine_interfaces WHERE mac_address = $1::macaddr RETURNING *",
                &[&macaddr],
            )
            .await?
            .into_iter()
            .map(MachineInterface::from)
            .collect::<Vec<MachineInterface>>())
    }

    pub async fn create(
        dbc: &crate::DatabaseConnection<'_>,
        machine: &Machine,
        segment: &NetworkSegment,
        macaddr: &MacAddress,
        address_v4: Option<Ipv4Addr>,
        address_v6: Option<Ipv6Addr>,
    ) -> CarbideResult<Self> {
        Ok(MachineInterface::from(
                dbc
                .query_one("INSERT INTO machine_interfaces (machine_id, segment_id, mac_address, address_ipv4, address_ipv6) VALUES ($1::uuid, $2::uuid, $3::macaddr, $4::inet, $5::inet) RETURNING *", &[&machine.id(), &segment.id(), &macaddr, &address_v4.and_then(|a| Some(IpAddr::from(a))), &address_v6.and_then(|a| Some(IpAddr::from(a)))])
                .await?,
        ))
    }
}

#[cfg(test)]
mod test {}
