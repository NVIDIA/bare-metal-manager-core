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
//! DHCPv6 SLAAC helpers used by `crate::dhcp::discover`.

use std::net::{IpAddr, Ipv6Addr};

use carbide_network::ip::IpAddressFamily;
use carbide_uuid::machine::MachineInterfaceId;
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use model::allocation_type::AllocationType;
use model::network_segment::NetworkSegment;
use sqlx::PgConnection;

use crate::CarbideError;

/// Compute the SLAAC address formed by applying RFC 4291 EUI-64 to `mac`.
///
/// Returns `None` unless `prefix` is an IPv6 /64, because modified EUI-64
/// interface identifiers are defined for 64-bit subnet prefixes.
pub fn slaac_gua_from_eui64(prefix: &IpNetwork, mac: &MacAddress) -> Option<Ipv6Addr> {
    // SLAAC EUI-64 is only meaningful for IPv6 /64 prefixes.
    let IpNetwork::V6(prefix) = prefix else {
        return None;
    };
    if prefix.prefix() != 64 {
        return None;
    }

    // Copy the network bits, then append the modified EUI-64 identifier.
    let mac = mac.bytes();
    let mut octets = prefix.network().octets();
    octets[8] = mac[0] ^ 0x02;
    octets[9] = mac[1];
    octets[10] = mac[2];
    octets[11] = 0xff;
    octets[12] = 0xfe;
    octets[13] = mac[3];
    octets[14] = mac[4];
    octets[15] = mac[5];

    Some(Ipv6Addr::from(octets))
}

/// Record one SLAAC observation for an interface when the segment is eligible.
///
/// A row is inserted only when the segment has exactly one IPv6 prefix and that
/// prefix is /64. Stateful DHCPv6 or static IPv6 assignments therefore
/// suppress SLAAC observation. Reserved segments serve DHCPv6 options without
/// creating observed SLAAC rows.
pub async fn observe_slaac_address(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    segment: &NetworkSegment,
    mac: &MacAddress,
) -> Result<(), CarbideError> {
    // Segment-level SLAAC availability is centralized on NetworkSegment so a
    // future segment flag can be added without auditing DHCP call sites.
    let Some(prefix) = segment.slaac_eligible() else {
        tracing::debug!(
            network_segment_id = %segment.id,
            allocation_strategy = ?segment.config.allocation_strategy,
            prefixes = ?segment.prefixes,
            "DHCPv6 SLAAC observation skipped because segment is not SLAAC-eligible"
        );
        return Ok(());
    };

    // A stateful/static IPv6 address already owns this interface family.
    if db::machine_interface_address::has_address_for_family(
        &mut *txn,
        interface_id,
        IpAddressFamily::Ipv6,
    )
    .await?
    {
        return Ok(());
    }

    // Persist the client-derived address and refresh DNS naming from the new state.
    if let Some(address) = slaac_gua_from_eui64(prefix, mac) {
        let address = IpAddr::V6(address);

        // TODO: This is a best-effort ownership check, not a complete
        // concurrency boundary. Static assignment and preallocation do not yet
        // share a segment lock with SLAAC observation, so they can still race
        // between this read and insert. A future PR should route DHCP, SLAAC,
        // and static address writes through one DB helper that locks the owning
        // segment, checks global address ownership, applies the replacement
        // policy, and writes the row.
        if let Some(existing) =
            db::machine_interface_address::find_by_address(&mut *txn, address).await?
        {
            if existing.id == interface_id {
                return Ok(());
            }

            return Err(CarbideError::FailedPrecondition(format!(
                "SLAAC address {address} is already allocated to interface {} on segment {}; refusing duplicate observation for interface {interface_id}",
                existing.id, existing.name,
            )));
        }

        db::machine_interface_address::insert(
            &mut *txn,
            interface_id,
            address,
            AllocationType::Slaac,
        )
        .await?;
        db::machine_interface::sync_hostname_after_address_assignment(
            txn,
            interface_id,
            segment.config.subdomain_id,
        )
        .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use carbide_test_support::value_scenarios;

    use super::*;

    // SLAAC EUI-64: a valid /64 receives the modified EUI-64 identifier, while
    // non-/64 and IPv4 prefixes are intentionally ineligible.
    #[test]
    fn computes_slaac_gua_from_eui64() {
        value_scenarios!(
            run = |(prefix, mac): (&str, &str)| {
                let prefix = IpNetwork::from_str(prefix).unwrap();
                let mac = MacAddress::from_str(mac).unwrap();
                slaac_gua_from_eui64(&prefix, &mac)
            };
            "ipv6 /64" {
                ("2001:db8::/64", "02:00:00:00:00:01") => Some(Ipv6Addr::from_str("2001:db8::ff:fe00:1").unwrap()),
            }

            "ineligible prefixes" {
                ("2001:db8::/80", "02:00:00:00:00:01") => None,
                ("192.0.2.0/24", "02:00:00:00:00:01") => None,
            }
        );
    }
}
