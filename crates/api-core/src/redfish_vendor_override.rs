/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! Database backed lookup for the operator BMC vendor pin.
//! Lives here as it bridges the crate holding the trait and the one querying.

use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use carbide_redfish::libredfish::conv;
use carbide_redfish::vendor_override::{BmcVendorOverrideResolver, VendorOverrideError};
use carbide_utils::redfish::parse_uri_host_ip;
use libredfish::model::service_root::RedfishVendor;
use sqlx::PgPool;

/// How long a resolved pin, or the absence of one, is reused before a fresh read.
/// Bounded staleness beats invalidation, as writes key on MAC and this on IP.
const DEFAULT_PIN_CACHE_TTL: Duration = Duration::from_secs(60);

/// Upper bound on cached BMC addresses, so probing unknown ones cannot grow the
/// cache without limit.
const PIN_CACHE_CAPACITY: u64 = 4096;

/// Resolves `bmc_vendor_override` for a BMC address, with a short lived cache.
pub(crate) struct DbBmcVendorOverrideResolver {
    db_pool: PgPool,
    /// Caches the absence of a pin as well as its presence, which is the point.
    /// Almost no BMC has one, so the common path would otherwise query Postgres.
    cache: moka::future::Cache<IpAddr, Option<RedfishVendor>>,
}

impl DbBmcVendorOverrideResolver {
    pub(crate) fn new(db_pool: PgPool) -> Self {
        Self::with_cache_ttl(db_pool, DEFAULT_PIN_CACHE_TTL)
    }

    /// Same, with an explicit TTL so tests can observe expiry without sleeping.
    pub(crate) fn with_cache_ttl(db_pool: PgPool, ttl: Duration) -> Self {
        Self {
            db_pool,
            cache: moka::future::Cache::builder()
                .max_capacity(PIN_CACHE_CAPACITY)
                .time_to_live(ttl)
                .build(),
        }
    }
}

#[async_trait]
impl BmcVendorOverrideResolver for DbBmcVendorOverrideResolver {
    async fn vendor_override(
        &self,
        host: &str,
    ) -> Result<Option<RedfishVendor>, VendorOverrideError> {
        // Pins resolve against `machine_interface_addresses.address`, so a BMC
        // reached by hostname has nothing to match on and reports no pin.
        let Some(ip) = parse_uri_host_ip(host) else {
            return Ok(None);
        };

        // `get_with` collapses concurrent lookups into one query. A read failure
        // resolves to no pin and caches, so an outage costs one query per TTL.
        Ok(self
            .cache
            .get_with(ip, async {
                let raw = match db::machine_interface::find_bmc_vendor_override_by_ip(
                    &self.db_pool,
                    ip,
                )
                .await
                {
                    Ok(raw) => raw,
                    Err(error) => {
                        tracing::warn!(
                            bmc = %ip,
                            %error,
                            "Failed to read bmc_vendor_override, BMC clients will use automatic detection"
                        );
                        return None;
                    }
                };

                // Parsing, the warning for an unusable name, and the refusal of
                // `Unknown` all live in the single place a name is interpreted.
                conv::redfish_vendor_override(host, raw.as_deref())
            })
            .await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seed one BMC interface at `ip` whose expected machine pins `pin`.
    async fn seed_pinned_bmc(pool: &PgPool, ip: IpAddr, mac: &str, pin: &str) {
        use model::network_segment::{
            AllocationStrategy, NetworkSegmentControllerState, NetworkSegmentType,
            NewNetworkSegment,
        };

        // Built through the real persist path rather than a hand written INSERT
        // so this fixture cannot drift from the segment schema.
        let segment_id = carbide_uuid::network::NetworkSegmentId::new();
        let mut txn = db::Transaction::begin(pool).await.expect("txn");
        db::network_segment::persist(
            NewNetworkSegment {
                id: segment_id,
                name: "pin-cache-segment".to_string(),
                subdomain_id: None,
                vpc_id: None,
                mtu: 1500,
                prefixes: Vec::new(),
                vlan_id: None,
                vni: None,
                segment_type: NetworkSegmentType::HostInband,
                can_stretch: Some(false),
                allocation_strategy: AllocationStrategy::Reserved,
                infer_slaac_eui64_addresses: false,
            },
            txn.as_pgconn(),
            NetworkSegmentControllerState::Ready,
        )
        .await
        .expect("segment");
        txn.commit().await.expect("commit segment");

        let interface: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO machine_interfaces \
                 (segment_id, mac_address, primary_interface, hostname, interface_type) \
             VALUES ($1, $2::macaddr, false, 'pin-cache-bmc', 'Bmc') RETURNING id",
        )
        .bind(segment_id)
        .bind(mac)
        .fetch_one(pool)
        .await
        .expect("interface");

        sqlx::query(
            "INSERT INTO machine_interface_addresses (interface_id, address) VALUES ($1, $2::inet)",
        )
        .bind(interface)
        .bind(ip)
        .execute(pool)
        .await
        .expect("address");

        sqlx::query(
            "INSERT INTO expected_machines (serial_number, bmc_mac_address, bmc_username, \
             bmc_password, bmc_vendor_override) VALUES ('PINCACHE1', $1::macaddr, 'root', 'p', $2)",
        )
        .bind(mac)
        .bind(pin)
        .execute(pool)
        .await
        .expect("expected machine");
    }

    /// A BMC reached by hostname has no address row to match, so it reports no
    /// pin rather than failing the client construction that asked.
    #[crate::sqlx_test]
    async fn a_hostname_addressed_bmc_has_no_pin(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resolver = DbBmcVendorOverrideResolver::new(pool);
        assert_eq!(resolver.vendor_override("bmc-01.example.test").await?, None);
        Ok(())
    }

    /// The cache is what makes a lookup per `create_client` affordable, so assert
    /// it caches, including the far more common answer of no pin at all.
    #[crate::sqlx_test]
    async fn resolved_pins_and_their_absence_are_both_cached(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ip: IpAddr = "192.0.2.77".parse()?;

        let cached = DbBmcVendorOverrideResolver::new(pool.clone());
        let uncached = DbBmcVendorOverrideResolver::with_cache_ttl(pool.clone(), Duration::ZERO);
        assert_eq!(cached.vendor_override(&ip.to_string()).await?, None);
        assert_eq!(uncached.vendor_override(&ip.to_string()).await?, None);

        seed_pinned_bmc(&pool, ip, "7A:7B:7C:7D:7E:77", "Dell").await;

        assert_eq!(
            cached.vendor_override(&ip.to_string()).await?,
            None,
            "the negative answer must still come from cache, the property that \
             keeps this off the hot path"
        );
        assert_eq!(
            uncached.vendor_override(&ip.to_string()).await?,
            Some(RedfishVendor::Dell),
            "a resolver whose entries have expired must see the new pin"
        );

        Ok(())
    }
}
