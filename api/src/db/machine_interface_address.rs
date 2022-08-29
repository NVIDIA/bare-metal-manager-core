use std::collections::HashMap;

use ipnetwork::IpNetwork;
use itertools::Itertools;
use sqlx::{FromRow, Postgres, Transaction};
use uuid::Uuid;

use crate::CarbideResult;

use super::UuidKeyedObjectFilter;

#[derive(Debug, FromRow, Clone)]
pub struct MachineInterfaceAddress {
    pub interface_id: Uuid,
    pub address: IpNetwork,
}

impl MachineInterfaceAddress {
    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }

    pub async fn find_for_interface(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<HashMap<Uuid, Vec<MachineInterfaceAddress>>> {
        let base_query = "SELECT * FROM machine_interface_addresses mia {where}".to_owned();

        Ok(match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, MachineInterfaceAddress>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, MachineInterfaceAddress>(
                    &base_query.replace("{where}", "WHERE mia.interface_id=$1"),
                )
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, MachineInterfaceAddress>(
                    &base_query.replace("{where}", "WHERE mia.interface_id=ANY($1)"),
                )
                .bind(list)
                .fetch_all(&mut *txn)
                .await?
            }
        }
        .into_iter()
        .into_group_map_by(|address| address.interface_id))
    }
}
