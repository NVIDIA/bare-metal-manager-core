use crate::db::UuidKeyedObjectFilter;
use crate::CarbideResult;
use ipnetwork::IpNetwork;
use sqlx::{Acquire, FromRow, Postgres, Transaction};
use uuid::Uuid;

#[derive(Debug, FromRow)]
pub struct NetworkPrefix {
    pub id: Uuid,
    pub segment_id: Uuid,
    pub prefix: IpNetwork,
    pub gateway: Option<IpNetwork>,
    pub num_reserved: i32,
}

#[derive(Debug)]
pub struct NewNetworkPrefix {
    pub prefix: IpNetwork,
    pub gateway: Option<IpNetwork>,
    pub num_reserved: i32,
}

impl NetworkPrefix {
    /*
     * Return a list of `NetworkPrefix`es for a segment.
     */
    pub async fn find_by_segment(
        txn: &mut Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
    ) -> CarbideResult<Vec<NetworkPrefix>> {
        let base_query = "SELECT * FROM network_prefixes {where}".to_owned();

        Ok(match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, NetworkPrefix>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, NetworkPrefix>(
                    &base_query.replace("{where}", "WHERE m.segment_id=$1"),
                )
                .bind(uuid)
                .fetch_all(&mut *txn)
                .await?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, NetworkPrefix>(
                    &base_query.replace("{where}", "WHERE m.segment_id=ANY($1)"),
                )
                .bind(list)
                .fetch_all(&mut *txn)
                .await?
            }
        })
    }

    /*
     * Create a prefix for a given segment id.
     *
     * Since this function will perform muliple inserts() it wraps the actions in a sub-transaction
     * and rolls it back if any of the inserts fail and wont leave half of them written.
     *
     * # Parameters
     *
     * txn: An in-progress transaction on a connection pool
     * segment: The UUID of a network segment, must already exist and be visible to this
     * transcation
     * prefixes: A slice of the `NewNetworkPrefix` to create.
     */
    pub async fn create_for(
        txn: &mut Transaction<'_, Postgres>,
        segment: &uuid::Uuid,
        prefixes: &[NewNetworkPrefix],
    ) -> CarbideResult<Vec<NetworkPrefix>> {
        let mut inner_transaction = txn.begin().await?;

        // https://github.com/launchbadge/sqlx/issues/294
        //
        // No way to insert multiple rows easily.  This is more readable than some hack to save
        // tiny amounts of time.
        //
        let mut inserted_prefixes: Vec<NetworkPrefix> = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            let new_prefix = sqlx::query_as("INSERT INTO network_prefixes (segment_id, prefix, gateway, num_reserved) VALUES ($1::uuid, $2::cidr, $3::inet, $4::integer) RETURNING *")
                                    .bind(segment)
                                    .bind(prefix.prefix)
                                    .bind(prefix.gateway)
                                    .bind(prefix.num_reserved)
                                    .fetch_one(&mut *inner_transaction).await?;

            inserted_prefixes.push(new_prefix);
        }

        inner_transaction.commit().await?;

        Ok(inserted_prefixes)
    }
}
