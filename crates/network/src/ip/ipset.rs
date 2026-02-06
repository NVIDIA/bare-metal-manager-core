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
use std::collections::BTreeSet;

use crate::ip::prefix::{IpPrefix, Ipv4Prefix, Ipv6Prefix, ToPrefix};

/// An IpSet is a specialized set-type data structure for IP addresses, which
/// internally is represented as a set of prefixes that cover the included
/// address space.
pub struct IpSet {
    included_prefixes: BTreeSet<IpPrefix>,
}

impl IpSet {
    /// Return whether the specified value is included in the set. The value can
    /// be an IpPrefix, an IpAddr, or anything else that implements ToPrefix.
    pub fn contains<P: ToPrefix>(&self, value: P) -> bool {
        let prefix = value.to_prefix();
        self.contains_prefix(&prefix)
    }

    fn contains_prefix(&self, prefix: &IpPrefix) -> bool {
        self.get_containing_prefix(prefix).is_some()
    }

    fn get_containing_prefix(&self, prefix: &IpPrefix) -> Option<IpPrefix> {
        self.included_prefixes
            .range(..=prefix)
            .last()
            .and_then(|included| included.contains(prefix).then_some(*included))
    }

    /// Add a prefix to the included set. If the set already contains the address
    /// space in the prefix, this is a no-op.
    pub fn add(&mut self, prefix: IpPrefix) {
        if self.contains_prefix(&prefix) {
            return;
        }

        // Remove all smaller subprefixes contained by what we're
        // about to insert.
        while let Some(subprefix) = self
            .included_prefixes
            .range(prefix..=prefix.get_last_subprefix())
            .find_map(|p| prefix.contains(p).then_some(*p))
        {
            self.included_prefixes.remove(&subprefix);
        }

        // Before inserting this prefix, look for its sibling and try to
        // aggregate with it (and then check for a sibling of the new aggregate,
        // and so on recursively).
        let mut prefix = prefix;
        while let Some(sibling) = prefix
            .get_sibling()
            .and_then(|sibling| self.included_prefixes.take(&sibling))
        {
            // We already know these are siblings, and therefore don't expect
            // this .try_aggregate() call to fail.
            let aggregated = prefix.try_aggregate(&sibling).unwrap();
            prefix = aggregated;
        }
        self.included_prefixes.insert(prefix);
    }

    /// Remove the address space represented by this prefix from the set.
    pub fn remove(&mut self, prefix: &IpPrefix) {
        let container = match self.get_containing_prefix(prefix) {
            Some(included) => included,
            None => {
                return;
            }
        };
        self.included_prefixes.remove(&container);

        // The prefix we removed may have been a superset of what we were asked
        // to remove, so let's recursively bifurcate/fragment it until we're at
        // the size requested. The non-matching fragments will be re-inserted
        // into the set.
        let mut container = container;
        while container != *prefix {
            container = match container.bifurcate().unwrap() {
                (c1, c2) if c1.contains(prefix) => {
                    self.included_prefixes.insert(c2);
                    c1
                }
                (c1, c2) if c2.contains(prefix) => {
                    self.included_prefixes.insert(c1);
                    c2
                }
                _ => unreachable!(),
            }
        }
    }

    /// Get the whole included address space as a list of aggregate prefixes.
    pub fn get_prefixes(&self) -> Vec<IpPrefix> {
        self.included_prefixes.iter().copied().collect()
    }

    /// Get just the IPv4 address space as a list of aggregate prefixes.
    pub fn get_ipv4_prefixes(&self) -> Vec<Ipv4Prefix> {
        self.included_prefixes
            .iter()
            .filter_map(|prefix| match prefix {
                IpPrefix::V4(ipv4_prefix) => Some(*ipv4_prefix),
                _ => None,
            })
            .collect()
    }

    /// Get just the IPv6 address space as a list of aggregate prefixes.
    pub fn get_ipv6_prefixes(&self) -> Vec<Ipv6Prefix> {
        self.included_prefixes
            .iter()
            .filter_map(|prefix| match prefix {
                IpPrefix::V6(ipv6_prefix) => Some(*ipv6_prefix),
                _ => None,
            })
            .collect()
    }

    /// Create a new set with nothing contained.
    pub fn new_empty() -> Self {
        Self {
            included_prefixes: BTreeSet::new(),
        }
    }
}

impl From<IpPrefix> for IpSet {
    fn from(value: IpPrefix) -> Self {
        let included_prefixes = BTreeSet::from([value]);
        Self { included_prefixes }
    }
}

impl<I> From<I> for IpSet
where
    I: IntoIterator<Item: ToPrefix>,
{
    fn from(value: I) -> Self {
        let mut ipset = Self::new_empty();
        let prefixes = value.into_iter();
        prefixes.for_each(|p| ipset.add(p.to_prefix()));
        ipset
    }
}

/// Given an iterator over prefix-like sources, return a list of prefixes
/// that cover all of the address space after merging adjacent prefixes and
/// deduplicating. This is a convenience function for constructing an IpSet
/// and getting its resulting prefixes.
pub fn aggregate_prefixes<I>(prefix_sources: I) -> Vec<IpPrefix>
where
    I: IntoIterator<Item: ToPrefix>,
{
    let ipset = IpSet::from(prefix_sources);
    ipset.get_prefixes()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_contains() {
        let ten_net = IpPrefix::from_str("10.0.0.0/8").unwrap();
        let last_ten_addr = IpPrefix::from_str("10.255.255.255/32").unwrap();
        let ipset = IpSet::from(ten_net);
        assert!(ipset.contains(ten_net));
        assert!(ipset.contains(last_ten_addr));

        let one_before = IpPrefix::from_str("9.255.255.255/32").unwrap();
        assert!(!ipset.contains(one_before));

        let one_after = IpPrefix::from_str("11.0.0.0/32").unwrap();
        assert!(!ipset.contains(one_after));
    }

    #[test]
    fn test_remove() {
        let mut ipset = IpSet::new_empty();
        ipset.add(IpPrefix::from_str("10.0.0.0/24").unwrap());
        let last_addr = IpPrefix::from_str("10.0.0.255/32").unwrap();
        ipset.remove(&last_addr);
        // We already removed this, doing it again should be a no-op.
        ipset.remove(&last_addr);
        let expected_prefixes: Vec<IpPrefix> = [
            "10.0.0.0/25",
            "10.0.0.128/26",
            "10.0.0.192/27",
            "10.0.0.224/28",
            "10.0.0.240/29",
            "10.0.0.248/30",
            "10.0.0.252/31",
            "10.0.0.254/32",
        ]
        .into_iter()
        .map(|p| IpPrefix::from_str(p).unwrap())
        .collect();
        assert_eq!(ipset.get_prefixes(), expected_prefixes);
    }

    #[test]
    fn test_auto_aggregation() {
        let mut ipset = IpSet::from(IpPrefix::from_str("10.0.0.0/24").unwrap());
        for p in [
            "10.0.1.4/30",
            "10.0.1.8/29",
            "10.0.1.16/28",
            "10.0.1.32/27",
            "10.0.1.64/26",
            "10.0.1.128/25",
        ] {
            ipset.add(IpPrefix::from_str(p).unwrap());
        }

        ipset.add(IpPrefix::from_str("10.0.1.0/24").unwrap());
        let expected_aggregate = IpPrefix::from_str("10.0.0.0/23").unwrap();
        assert_eq!(ipset.get_prefixes().as_slice(), &[expected_aggregate]);
    }

    #[test]
    fn test_bulk_address_aggregation() {
        let start_addr = Ipv4Addr::from_str("10.0.0.0").unwrap();
        let end_addr = Ipv4Addr::from_str("10.1.0.0").unwrap();
        let mut ipv4_address_prefixes: Vec<_> =
            (start_addr..end_addr).map(|a| a.to_prefix()).collect();
        ipv4_address_prefixes.as_mut_slice().reverse();
        let ipset = IpSet::from(ipv4_address_prefixes.as_slice());
        let expected_address_space = IpPrefix::from_str("10.0.0.0/16").unwrap();
        assert_eq!(ipset.get_prefixes().as_slice(), &[expected_address_space]);
    }

    #[test]
    fn test_aggregate_prefixes() {
        let p1 = IpPrefix::from_str("10.0.0.0/24").unwrap();
        let p2 = IpPrefix::from_str("10.0.1.0/24").unwrap();
        let p3 = IpPrefix::from_str("10.0.2.0/23").unwrap();
        let p4 = IpPrefix::from_str("2001:db8:0000::/34").unwrap();
        let p5 = IpPrefix::from_str("2001:db8:4000::/34").unwrap();
        let p6 = IpPrefix::from_str("2001:db8:8000::/33").unwrap();
        let mut before = vec![p1, p2, p3, p4, p5, p6];
        // Let's not make it too easy.
        before.reverse();

        let after = aggregate_prefixes(before.as_slice());
        let a1 = IpPrefix::from_str("10.0.0.0/22").unwrap();
        let a2 = IpPrefix::from_str("2001:db8::/32").unwrap();
        assert_eq!(after.as_slice(), &[a1, a2]);
    }
}
