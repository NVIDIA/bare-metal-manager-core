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

    use carbide_test_support::{Check, check_values};

    use super::*;

    /// Parse a prefix string into an `IpPrefix`, panicking on malformed input.
    /// All the strings below are test literals known to be valid.
    fn pfx(s: &str) -> IpPrefix {
        IpPrefix::from_str(s).unwrap_or_else(|e| panic!("bad test prefix {s:?}: {e}"))
    }

    /// Parse a slice of prefix strings into owned `IpPrefix` values.
    fn pfxs(strs: &[&str]) -> Vec<IpPrefix> {
        strs.iter().map(|s| pfx(s)).collect()
    }

    /// Build an `IpSet` by adding each of the given prefix strings, then return
    /// its aggregate prefixes as strings for easy table comparison.
    fn add_all_and_dump(strs: &[&str]) -> Vec<String> {
        let mut ipset = IpSet::new_empty();
        for s in strs {
            ipset.add(pfx(s));
        }
        ipset.get_prefixes().iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn membership_covers_set_and_gaps() {
        // The set is the whole 10/8 net; check addresses and prefixes inside it,
        // on each boundary, and just outside on either side.
        let ipset = IpSet::from(pfx("10.0.0.0/8"));
        check_values(
            [
                Check {
                    scenario: "the defining prefix itself",
                    input: "10.0.0.0/8",
                    expect: true,
                },
                Check {
                    scenario: "first address in range",
                    input: "10.0.0.0/32",
                    expect: true,
                },
                Check {
                    scenario: "last address in range",
                    input: "10.255.255.255/32",
                    expect: true,
                },
                Check {
                    scenario: "an interior subprefix",
                    input: "10.128.0.0/9",
                    expect: true,
                },
                Check {
                    scenario: "a deep interior address",
                    input: "10.1.2.3/32",
                    expect: true,
                },
                Check {
                    scenario: "one address before the range",
                    input: "9.255.255.255/32",
                    expect: false,
                },
                Check {
                    scenario: "one address after the range",
                    input: "11.0.0.0/32",
                    expect: false,
                },
                Check {
                    scenario: "a wider prefix that is not contained",
                    input: "10.0.0.0/7",
                    expect: false,
                },
                Check {
                    scenario: "an unrelated v4 prefix",
                    input: "192.168.0.0/16",
                    expect: false,
                },
                Check {
                    scenario: "an IPv6 prefix is never in a v4-only set",
                    input: "2001:db8::/32",
                    expect: false,
                },
            ],
            |s| ipset.contains(pfx(s)),
        );
    }

    #[test]
    fn membership_of_the_empty_set_is_always_false() {
        let ipset = IpSet::new_empty();
        check_values(
            [
                Check {
                    scenario: "v4 address",
                    input: "10.0.0.1/32",
                    expect: false,
                },
                Check {
                    scenario: "v4 prefix",
                    input: "0.0.0.0/0",
                    expect: false,
                },
                Check {
                    scenario: "v6 prefix",
                    input: "::/0",
                    expect: false,
                },
            ],
            |s| ipset.contains(pfx(s)),
        );
    }

    #[test]
    fn membership_of_disjoint_v4_v6_set() {
        // A set holding both a v4 and a v6 prefix; each family answers
        // independently and never crosses over.
        let ipset = IpSet::from([pfx("10.0.0.0/8"), pfx("2001:db8::/32")]);
        check_values(
            [
                Check {
                    scenario: "inside the v4 member",
                    input: "10.5.5.5/32",
                    expect: true,
                },
                Check {
                    scenario: "inside the v6 member",
                    input: "2001:db8:abcd::/48",
                    expect: true,
                },
                Check {
                    scenario: "outside the v4 member",
                    input: "11.0.0.0/8",
                    expect: false,
                },
                Check {
                    scenario: "outside the v6 member",
                    input: "2001:db9::/32",
                    expect: false,
                },
            ],
            |s| ipset.contains(pfx(s)),
        );
    }

    #[test]
    fn adding_prefixes_aggregates_and_dedups() {
        // Each row builds a fresh set from the given inputs and asserts the
        // resulting aggregate prefixes. Order of insertion must not matter.
        check_values(
            [
                Check {
                    scenario: "single prefix is stored verbatim",
                    input: &["10.0.0.0/24"][..],
                    expect: vec!["10.0.0.0/24".to_string()],
                },
                Check {
                    scenario: "exact duplicate is a no-op",
                    input: &["10.0.0.0/24", "10.0.0.0/24"][..],
                    expect: vec!["10.0.0.0/24".to_string()],
                },
                Check {
                    scenario: "a subprefix already covered is absorbed",
                    input: &["10.0.0.0/8", "10.1.2.0/24"][..],
                    expect: vec!["10.0.0.0/8".to_string()],
                },
                Check {
                    scenario: "a superprefix swallows an existing entry",
                    input: &["10.1.2.0/24", "10.0.0.0/8"][..],
                    expect: vec!["10.0.0.0/8".to_string()],
                },
                Check {
                    scenario: "two siblings aggregate into their supernet",
                    input: &["10.0.0.0/24", "10.0.1.0/24"][..],
                    expect: vec!["10.0.0.0/23".to_string()],
                },
                Check {
                    scenario: "siblings aggregate regardless of insertion order",
                    input: &["10.0.1.0/24", "10.0.0.0/24"][..],
                    expect: vec!["10.0.0.0/23".to_string()],
                },
                Check {
                    scenario: "non-sibling neighbors stay separate",
                    input: &["10.0.1.0/24", "10.0.2.0/24"][..],
                    expect: vec!["10.0.1.0/24".to_string(), "10.0.2.0/24".to_string()],
                },
                Check {
                    scenario: "cascading aggregation up several levels",
                    input: &[
                        "10.0.0.0/26",
                        "10.0.0.64/26",
                        "10.0.0.128/26",
                        "10.0.0.192/26",
                    ][..],
                    expect: vec!["10.0.0.0/24".to_string()],
                },
                Check {
                    scenario: "filling a /24 from a /25 plus power-of-two pieces",
                    input: &[
                        "10.0.1.4/30",
                        "10.0.1.8/29",
                        "10.0.1.16/28",
                        "10.0.1.32/27",
                        "10.0.1.64/26",
                        "10.0.1.128/25",
                        "10.0.0.0/24",
                        "10.0.1.0/30",
                    ][..],
                    expect: vec!["10.0.0.0/23".to_string()],
                },
                Check {
                    scenario: "a v4 and a v6 prefix coexist, v4 sorts first",
                    input: &["2001:db8::/32", "10.0.0.0/8"][..],
                    expect: vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
                },
                Check {
                    scenario: "v6 siblings aggregate too",
                    input: &["2001:db8:0000::/34", "2001:db8:4000::/34"][..],
                    expect: vec!["2001:db8::/33".to_string()],
                },
                Check {
                    scenario: "a default route swallows everything in its family",
                    input: &["0.0.0.0/0", "10.0.0.0/8", "192.168.0.0/16"][..],
                    expect: vec!["0.0.0.0/0".to_string()],
                },
            ],
            add_all_and_dump,
        );
    }

    #[test]
    fn auto_aggregation_collapses_a_full_supernet() {
        // The original `test_auto_aggregation`: a /24 plus the pieces of its
        // sibling /24 collapse to a single /23.
        let mut ipset = IpSet::from(pfx("10.0.0.0/24"));
        for s in [
            "10.0.1.4/30",
            "10.0.1.8/29",
            "10.0.1.16/28",
            "10.0.1.32/27",
            "10.0.1.64/26",
            "10.0.1.128/25",
            "10.0.1.0/30",
        ] {
            ipset.add(pfx(s));
        }
        ipset.add(pfx("10.0.1.0/24"));
        assert_eq!(ipset.get_prefixes(), pfxs(&["10.0.0.0/23"]));
    }

    #[test]
    fn removing_fragments_the_containing_prefix() {
        // The original `test_remove`: removing the last /32 from a /24 leaves a
        // descending staircase of fragments; removing it again is a no-op.
        let mut ipset = IpSet::new_empty();
        ipset.add(pfx("10.0.0.0/24"));
        let last_addr = pfx("10.0.0.255/32");
        ipset.remove(&last_addr);
        ipset.remove(&last_addr);
        let expected = pfxs(&[
            "10.0.0.0/25",
            "10.0.0.128/26",
            "10.0.0.192/27",
            "10.0.0.224/28",
            "10.0.0.240/29",
            "10.0.0.248/30",
            "10.0.0.252/31",
            "10.0.0.254/32",
        ]);
        assert_eq!(ipset.get_prefixes(), expected);
    }

    #[test]
    fn remove_outcomes() {
        // Each row starts from a set built from the first slice, removes the
        // second prefix, then dumps the resulting aggregate prefixes.
        struct Case {
            scenario: &'static str,
            start: &'static [&'static str],
            remove: &'static str,
            expect: Vec<String>,
        }
        let cases = [
            Case {
                scenario: "removing a member empties the set",
                start: &["10.0.0.0/24"],
                remove: "10.0.0.0/24",
                expect: vec![],
            },
            Case {
                scenario: "removing something absent is a no-op",
                start: &["10.0.0.0/24"],
                remove: "192.168.0.0/24",
                expect: vec!["10.0.0.0/24".to_string()],
            },
            Case {
                scenario: "removing from the empty set is a no-op",
                start: &[],
                remove: "10.0.0.0/24",
                expect: vec![],
            },
            Case {
                scenario: "removing a half leaves the other half",
                start: &["10.0.0.0/23"],
                remove: "10.0.0.0/24",
                expect: vec!["10.0.1.0/24".to_string()],
            },
            Case {
                scenario: "removing the high half leaves the low half",
                start: &["10.0.0.0/23"],
                remove: "10.0.1.0/24",
                expect: vec!["10.0.0.0/24".to_string()],
            },
            Case {
                scenario: "removing one member leaves disjoint others untouched",
                start: &["10.0.0.0/24", "192.168.0.0/24"],
                remove: "10.0.0.0/24",
                expect: vec!["192.168.0.0/24".to_string()],
            },
            Case {
                scenario: "removing a v6 member leaves the v4 member",
                start: &["10.0.0.0/8", "2001:db8::/32"],
                remove: "2001:db8::/32",
                expect: vec!["10.0.0.0/8".to_string()],
            },
        ];
        check_values(
            cases.map(|c| Check {
                scenario: c.scenario,
                input: (c.start, c.remove),
                expect: c.expect,
            }),
            |(start, remove)| {
                let mut ipset = IpSet::from(pfxs(start));
                ipset.remove(&pfx(remove));
                ipset.get_prefixes().iter().map(|p| p.to_string()).collect()
            },
        );
    }

    #[test]
    fn family_filtered_getters_split_by_address_family() {
        // get_ipv4_prefixes / get_ipv6_prefixes each keep only their family;
        // get_prefixes keeps both. Project each set to (v4 strings, v6 strings,
        // total len) so the mixed, single-family, and empty cases are all rows.
        let project = |ipset: IpSet| {
            let v4: Vec<String> = ipset
                .get_ipv4_prefixes()
                .iter()
                .map(|p| p.to_string())
                .collect();
            let v6: Vec<String> = ipset
                .get_ipv6_prefixes()
                .iter()
                .map(|p| p.to_string())
                .collect();
            (v4, v6, ipset.get_prefixes().len())
        };
        check_values(
            [
                Check {
                    scenario: "mixed set splits into its two families",
                    input: IpSet::from([
                        pfx("10.0.0.0/8"),
                        pfx("192.168.0.0/16"),
                        pfx("2001:db8::/32"),
                        pfx("fd00::/8"),
                    ]),
                    expect: (
                        vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
                        vec!["2001:db8::/32".to_string(), "fd00::/8".to_string()],
                        4,
                    ),
                },
                Check {
                    scenario: "v4-only set yields nothing from the v6 getter",
                    input: IpSet::from(pfx("10.0.0.0/8")),
                    expect: (vec!["10.0.0.0/8".to_string()], vec![], 1),
                },
                Check {
                    scenario: "v6-only set yields nothing from the v4 getter",
                    input: IpSet::from(pfx("2001:db8::/32")),
                    expect: (vec![], vec!["2001:db8::/32".to_string()], 1),
                },
                Check {
                    scenario: "empty set yields nothing from either getter",
                    input: IpSet::new_empty(),
                    expect: (vec![], vec![], 0),
                },
            ],
            project,
        );
    }

    #[test]
    fn from_iterator_constructs_an_aggregated_set() {
        // The `From<IntoIterator>` impl runs every item through `add`, so the
        // result is already aggregated and deduplicated.
        check_values(
            [
                Check {
                    scenario: "empty iterator yields the empty set",
                    input: &[][..],
                    expect: Vec::<String>::new(),
                },
                Check {
                    scenario: "duplicates collapse",
                    input: &["10.0.0.0/24", "10.0.0.0/24", "10.0.0.0/24"][..],
                    expect: vec!["10.0.0.0/24".to_string()],
                },
                Check {
                    scenario: "siblings aggregate",
                    input: &["10.0.0.0/24", "10.0.1.0/24"][..],
                    expect: vec!["10.0.0.0/23".to_string()],
                },
            ],
            |strs: &[&str]| {
                let ipset = IpSet::from(pfxs(strs));
                ipset.get_prefixes().iter().map(|p| p.to_string()).collect()
            },
        );
    }

    #[test]
    fn bulk_address_aggregation_merges_a_full_run() {
        // The original `test_bulk_address_aggregation`: every /32 from 10.0.0.0
        // up to (excluding) 10.1.0.0 covers exactly 10.0.0.0/16.
        let start_addr = Ipv4Addr::from_str("10.0.0.0").unwrap();
        let end_addr = Ipv4Addr::from_str("10.1.0.0").unwrap();
        let mut prefixes: Vec<_> = (start_addr..end_addr).map(|a| a.to_prefix()).collect();
        prefixes.as_mut_slice().reverse();
        let ipset = IpSet::from(prefixes.as_slice());
        assert_eq!(ipset.get_prefixes(), pfxs(&["10.0.0.0/16"]));
    }

    #[test]
    fn aggregate_prefixes_merges_and_sorts() {
        // The original `test_aggregate_prefixes`, generalized: each row feeds a
        // (deliberately scrambled) list through the free `aggregate_prefixes`
        // helper and asserts the merged, v4-before-v6 result.
        check_values(
            [
                Check {
                    scenario: "empty input yields nothing",
                    input: &[][..],
                    expect: Vec::<String>::new(),
                },
                Check {
                    scenario: "a single prefix passes through",
                    input: &["10.0.0.0/24"][..],
                    expect: vec!["10.0.0.0/24".to_string()],
                },
                Check {
                    scenario: "mixed v4 and v6 merge within each family and sort",
                    input: &[
                        "2001:db8:8000::/33",
                        "2001:db8:4000::/34",
                        "2001:db8:0000::/34",
                        "10.0.2.0/23",
                        "10.0.1.0/24",
                        "10.0.0.0/24",
                    ][..],
                    expect: vec!["10.0.0.0/22".to_string(), "2001:db8::/32".to_string()],
                },
            ],
            |strs: &[&str]| {
                aggregate_prefixes(pfxs(strs))
                    .iter()
                    .map(|p| p.to_string())
                    .collect()
            },
        );
    }
}
