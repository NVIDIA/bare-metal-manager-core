use std::net::IpAddr;

use sqlx::{FromRow, Postgres, Transaction};

use super::DatabaseError;
use crate::{db::BIND_LIMIT, CarbideError, CarbideResult};

#[derive(FromRow)]
pub struct RouteServer {
    pub address: IpAddr,
}

impl RouteServer {
    pub async fn get_or_create(
        txn: &mut Transaction<'_, Postgres>,
        addresses: &[IpAddr],
    ) -> CarbideResult<Vec<IpAddr>> {
        let route_servers = RouteServer::get(txn).await?;
        if route_servers.is_empty() {
            if addresses.is_empty() {
                return Err(CarbideError::MissingArgument(
                    "RouteServer::get_or_create: No addresses provided",
                ));
            }

            if addresses.len() > BIND_LIMIT {
                return Err(CarbideError::InvalidArgument(format!(
                    "RouteServer::get_or_create: {} addresses exceeds bind limit ({})",
                    addresses.len(),
                    BIND_LIMIT
                )));
            }

            // this builds an insert query that inserts multiple rows from the addresses arg, but only if the table is empty
            let query = r#"INSERT INTO route_servers (address) select a from ("#;
            let mut qb = sqlx::QueryBuilder::new(query);

            qb.push_values(addresses.iter(), |mut b, v| {
                b.push_bind(v);
            });
            qb.push(r#") s(a)  where NOT EXISTS (select * from route_servers)"#);

            let query = qb.build();

            let result = query.execute(&mut **txn).await.map_err(|e| {
                DatabaseError::new(file!(), line!(), "RouteServer::get_or_create", e)
            })?;

            if result.rows_affected() != addresses.len() as u64 {
                let msg = format!(
                    "Unexpected result adding route servers: {:?}, rows_affected: {}",
                    addresses,
                    result.rows_affected()
                );
                tracing::warn!("{msg}");
                return Err(crate::CarbideError::GenericError(msg));
            }
            Ok(addresses.to_vec())
        } else {
            Ok(route_servers.into_iter().map(|rs| rs.address).collect())
        }
    }

    pub async fn get(txn: &mut Transaction<'_, Postgres>) -> CarbideResult<Vec<RouteServer>> {
        let query = r#"SELECT * FROM route_servers;"#;

        Ok(sqlx::query_as::<_, RouteServer>(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?)
    }

    pub async fn add(
        txn: &mut Transaction<'_, Postgres>,
        addresses: &[IpAddr],
    ) -> CarbideResult<()> {
        if !addresses.is_empty() {
            let query = r#"INSERT INTO route_servers "#;
            let mut qb = sqlx::QueryBuilder::new(query);

            qb.push_values(addresses.iter(), |mut b, v| {
                b.push_bind(v);
            });
            let query = qb.build();

            query
                .execute(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "RouteServer::add", e))?;
        }
        Ok(())
    }

    pub async fn remove(
        txn: &mut Transaction<'_, Postgres>,
        addresses: &Vec<IpAddr>,
    ) -> CarbideResult<()> {
        if !addresses.is_empty() {
            let query = r#"DELETE FROM route_servers where address=ANY($1);"#;
            sqlx::query(query)
                .bind(addresses)
                .execute(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "RouteServer::add", e))?;
        }
        Ok(())
    }

    pub async fn replace(
        txn: &mut Transaction<'_, Postgres>,
        addresses: &[IpAddr],
    ) -> CarbideResult<()> {
        let query = r#"DELETE FROM route_servers;"#;
        let _result = sqlx::query(query)
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        if !addresses.is_empty() {
            Self::get_or_create(txn, addresses).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[sqlx::test]
pub async fn test_create(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let expected_servers = vec![
        IpAddr::from_str("1.2.3.4")?,
        IpAddr::from_str("2.3.4.5")?,
        IpAddr::from_str("3.4.5.6")?,
    ];

    let mut txn = pool.begin().await?;

    let result = RouteServer::get_or_create(&mut txn, &expected_servers).await?;

    txn.commit().await?;

    assert_eq!(result, expected_servers);

    Ok(())
}

#[cfg(test)]
#[sqlx::test]
pub async fn test_duplicate_create(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let expected_servers = vec![
        IpAddr::from_str("1.2.3.4")?,
        IpAddr::from_str("2.3.4.5")?,
        IpAddr::from_str("3.4.5.6")?,
    ];

    let mut txn = pool.begin().await?;

    let result = RouteServer::get_or_create(&mut txn, &expected_servers).await?;

    txn.commit().await?;

    assert_eq!(result, expected_servers);

    let ignored_servers = vec![
        IpAddr::from_str("1.1.1.1")?,
        IpAddr::from_str("2.2.2.2")?,
        IpAddr::from_str("3.3.3.3")?,
        IpAddr::from_str("4.4.4.4")?,
    ];

    let mut txn = pool.begin().await?;

    let result = RouteServer::get_or_create(&mut txn, &ignored_servers).await?;

    txn.commit().await?;
    assert_eq!(result, expected_servers);

    Ok(())
}

#[cfg(test)]
use std::str::FromStr;

#[cfg(test)]
#[sqlx::test]
pub async fn test_replace(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let expected_servers = vec![
        IpAddr::from_str("1.2.3.4")?,
        IpAddr::from_str("2.3.4.5")?,
        IpAddr::from_str("3.4.5.6")?,
    ];

    let mut txn = pool.begin().await?;

    let result = RouteServer::get_or_create(&mut txn, &expected_servers).await?;

    txn.commit().await?;

    assert_eq!(result, expected_servers);

    let new_servers = vec![
        IpAddr::from_str("1.1.1.1")?,
        IpAddr::from_str("2.2.2.2")?,
        IpAddr::from_str("3.3.3.3")?,
        IpAddr::from_str("4.4.4.4")?,
    ];

    let mut txn = pool.begin().await?;

    RouteServer::replace(&mut txn, &new_servers).await?;
    let result: Vec<IpAddr> = RouteServer::get(&mut txn)
        .await?
        .into_iter()
        .map(|a| a.address)
        .collect();

    txn.commit().await?;
    assert_eq!(result, new_servers);

    Ok(())
}
