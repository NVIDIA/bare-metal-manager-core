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

//! Admission for tenant address-space reuse across the site routing graph.
//!
//! Every routing-graph writer first takes one transaction-scoped site lock,
//! then compares its candidate state with the rows visible in that transaction.
//! Existing overlap is preserved during contraction, while newly introduced
//! overlap must be exact cross-VPC tenant reuse and pass the full isolation
//! policy. Startup runs the same live-state check after any database seeding and
//! before routing controllers or listeners start.
//!
//! The evaluator loads addresses first and avoids the more expensive peering,
//! security-group, and retained-instance projection when no tenant reuse is
//! present. Detailed resource identifiers stay in operator logs; client errors
//! deliberately expose only the stable violation category.

use std::collections::{HashMap, HashSet};
use std::fmt;

use carbide_network::virtualization::VpcVirtualizationType;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::network::{NetworkPrefixId, NetworkSegmentId};
use carbide_uuid::network_security_group::NetworkSecurityGroupId;
use carbide_uuid::site_prefix::SitePrefixId;
use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use ipnetwork::IpNetwork;
use model::instance::config::network::{
    InstanceInterfaceRoutingProfile, InstanceNetworkConfig, NetworkDetails,
};
use model::network_security_group::{NetworkSecurityGroup, NetworkSecurityGroupRuleAction};
use model::network_segment::{NetworkSegment, NetworkSegmentType, NewNetworkSegment};
use model::site_prefix::{
    SitePrefix, SitePrefixAuthority, SitePrefixLifecycleState, SitePrefixRoutingScope,
};
use model::vpc::{Vpc, VpcVirtualizationTypeCapabilities};
use model::vpc_prefix::NewVpcPrefix;
use sqlx::PgConnection;

use crate::cfg::file::{
    CarbideConfig, FnnRoutingProfileConfig, VpcIsolationBehaviorType, VpcPeeringPolicy,
};
use crate::{CarbideError, CarbideResult};

const OVERLAPPING_ADDRESS_SPACE: &str =
    "requested address space overlaps existing routed address space";
const INELIGIBLE_OVERLAP: &str =
    "requested address space is not eligible for tenant prefix overlap";
const REACHABLE_OVERLAP: &str = "requested routing would expose overlapping tenant address space";
const UNSAFE_POLICY: &str =
    "active tenant routing policy is not safe for overlapping address space";

/// Identifies the resource category that contributes a routed prefix.
///
/// `Vpc` retains the optional SitePrefix link used for eligibility. `Network`
/// has no ID for a candidate segment prefix that has not been persisted.
#[derive(Clone, Debug, Eq, PartialEq)]
enum AddressSource {
    /// A VPC prefix whose SitePrefix association determines reuse eligibility.
    Vpc {
        site_prefix_id: Option<SitePrefixId>,
    },
    /// A direct NetworkSegment prefix, which is never eligible for reuse.
    Network { id: Option<NetworkPrefixId> },
}

/// Stable typed identity for one persisted or candidate routed address.
///
/// Variant order matches the rendered namespace order. Derived ordering gives
/// overlap pairs a canonical identity and gives callers a stable order when
/// they explicitly sort an address inventory.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum AddressKey {
    CandidateNetwork(usize),
    CandidateVpc(VpcPrefixId),
    Network(NetworkPrefixId),
    Vpc(VpcPrefixId),
}

impl fmt::Display for AddressKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CandidateNetwork(index) => {
                write!(formatter, "candidate-network-prefix:{index}")
            }
            Self::CandidateVpc(id) => write!(formatter, "candidate-vpc-prefix:{id}"),
            Self::Network(id) => write!(formatter, "network-prefix:{id}"),
            Self::Vpc(id) => write!(formatter, "vpc-prefix:{id}"),
        }
    }
}

/// Normalized address inventory used by both persisted and candidate checks.
#[derive(Clone, Debug)]
struct RoutedAddress {
    /// Stable identity used to distinguish pre-existing overlap from a new pair.
    key: AddressKey,
    vpc_id: VpcId,
    prefix: IpNetwork,
    source: AddressSource,
}

/// Routing references retained by one instance across current and pending config.
///
/// Pending old and new configurations both remain relevant until the transition
/// completes. An unresolved retained reference therefore fails closed whenever
/// tenant address reuse is active.
#[derive(Debug)]
struct InstancePath {
    instance_id: InstanceId,
    vpc_ids: HashSet<VpcId>,
    network_security_group_id: Option<NetworkSecurityGroupId>,
    has_routing_override: bool,
    has_unresolved_reference: bool,
}

/// Transaction-consistent routing state evaluated for one admission decision.
///
/// `from_addresses` builds the inexpensive address phase. `apply_policy_paths`
/// enriches it only when an exact tenant-reuse pair requires policy analysis.
#[derive(Debug)]
struct RoutingState<'a> {
    vpcs: HashMap<VpcId, &'a Vpc>,
    site_prefixes: HashMap<SitePrefixId, &'a SitePrefix>,
    addresses: Vec<RoutedAddress>,
    admin_only_vpcs: HashSet<VpcId>,
    peerings: Vec<(VpcId, VpcId)>,
    network_security_groups: HashMap<NetworkSecurityGroupId, NetworkSecurityGroup>,
    instance_paths: Vec<InstancePath>,
}

/// Cached result of the single pairwise address scan for a `RoutingState`.
///
/// `occupancy_pairs` detects candidate expansion, `all_indices` covers every
/// containment conflict, and `tenant_reuse_indices` selects exact cross-VPC
/// VPC-prefix pairs that require the full routing-policy check.
#[derive(Debug)]
struct OverlapAnalysis {
    occupancy_pairs: HashSet<(AddressKey, AddressKey)>,
    all_indices: Vec<(usize, usize)>,
    tenant_reuse_indices: Vec<(usize, usize)>,
}

impl<'a> RoutingState<'a> {
    /// Builds the address-only state while retaining soft-deleted routing rows.
    ///
    /// Generated NetworkPrefix children are omitted because their VpcPrefix
    /// parent is the routed claim; direct segment prefixes remain independent.
    fn from_addresses(snapshot: &'a db::routing_safety::RoutingAddressSnapshot) -> Self {
        let vpcs = snapshot.vpcs.iter().map(|vpc| (vpc.id, vpc)).collect();
        let site_prefixes = snapshot
            .site_prefixes
            .iter()
            .map(|prefix| (prefix.id, prefix))
            .collect();
        let mut addresses = snapshot
            .vpc_prefixes
            .iter()
            .map(|prefix| RoutedAddress {
                key: AddressKey::Vpc(prefix.id),
                vpc_id: prefix.vpc_id,
                prefix: prefix.config.prefix,
                source: AddressSource::Vpc {
                    site_prefix_id: prefix.site_prefix_id,
                },
            })
            .collect::<Vec<_>>();

        let mut vpcs_with_admin_segments = HashSet::new();
        let mut vpcs_with_non_admin_segments = HashSet::new();
        for segment in &snapshot.network_segments {
            let Some(vpc_id) = segment.config.vpc_id else {
                continue;
            };
            if segment.config.segment_type == NetworkSegmentType::Admin {
                vpcs_with_admin_segments.insert(vpc_id);
            } else {
                vpcs_with_non_admin_segments.insert(vpc_id);
            }
            addresses.extend(
                segment
                    .prefixes
                    .iter()
                    .filter(|prefix| prefix.vpc_prefix_id.is_none())
                    .map(|prefix| RoutedAddress {
                        key: AddressKey::Network(prefix.id),
                        vpc_id,
                        prefix: prefix.prefix,
                        source: AddressSource::Network {
                            id: Some(prefix.id),
                        },
                    }),
            );
        }
        addresses.sort_by_key(|address| address.key);
        let admin_only_vpcs = vpcs_with_admin_segments
            .difference(&vpcs_with_non_admin_segments)
            .copied()
            .collect();

        Self {
            vpcs,
            site_prefixes,
            addresses,
            admin_only_vpcs,
            peerings: Vec::new(),
            network_security_groups: HashMap::new(),
            instance_paths: Vec::new(),
        }
    }

    /// Adds peer visibility and every retained instance path to the address state.
    ///
    /// Callers invoke this only after exact tenant reuse is found. Current and
    /// pending old/new instance configs are unioned, and a missing retained row
    /// remains unresolved so policy validation fails closed.
    fn apply_policy_paths(
        &mut self,
        snapshot: &db::routing_safety::RoutingPolicySnapshot,
        addresses: &db::routing_safety::RoutingAddressSnapshot,
    ) {
        let segment_vpcs = addresses
            .network_segments
            .iter()
            .map(|segment| (segment.id, segment.config.vpc_id))
            .collect::<HashMap<_, _>>();
        let vpc_prefix_vpcs = addresses
            .vpc_prefixes
            .iter()
            .map(|prefix| (prefix.id, prefix.vpc_id))
            .collect::<HashMap<_, _>>();
        self.instance_paths = snapshot
            .instances
            .iter()
            .map(|instance| {
                let mut configs = vec![&instance.network_config.0];
                if let Some(update) = &instance.update_network_config_request {
                    configs.push(&update.0.old_config);
                    configs.push(&update.0.new_config);
                }
                let mut vpc_ids = HashSet::new();
                let mut has_routing_override = false;
                let mut has_unresolved_reference = false;
                for config in configs {
                    collect_instance_path(
                        config,
                        &segment_vpcs,
                        &vpc_prefix_vpcs,
                        &mut vpc_ids,
                        &mut has_routing_override,
                        &mut has_unresolved_reference,
                    );
                }
                InstancePath {
                    instance_id: instance.id,
                    vpc_ids,
                    network_security_group_id: instance.network_security_group_id.clone(),
                    has_routing_override,
                    has_unresolved_reference,
                }
            })
            .collect();
        self.instance_paths.sort_by_key(|path| path.instance_id);
        self.peerings = snapshot
            .peerings
            .iter()
            .map(|peering| (peering.vpc_id, peering.peer_vpc_id))
            .collect();
        self.peerings.sort();
        self.network_security_groups = snapshot
            .network_security_groups
            .iter()
            .map(|group| (group.id.clone(), group.clone()))
            .collect();
    }

    /// Returns whether this is the configured, unconsumed startup admin VPC.
    ///
    /// Segment type alone is insufficient: callers can create `Admin` segments.
    /// The startup VPC is identified by its internal tenant and configured VNI.
    /// Its exemption is revoked as soon as a retained instance or peering
    /// references it; no consumed path is assumed to remain control-only.
    fn is_unconsumed_admin_vpc(&self, config: &CarbideConfig, vpc: &Vpc) -> bool {
        let Some(configured_vni) = config
            .fnn
            .as_ref()
            .and_then(|fnn| fnn.admin_vpc.as_ref())
            .filter(|admin| admin.enabled)
            .and_then(|admin| admin.vpc_vni)
            .and_then(|vni| i32::try_from(vni).ok())
        else {
            return false;
        };

        self.admin_only_vpcs.contains(&vpc.id)
            && vpc.config.tenant_organization_id == "carbide_internal"
            && vpc.config.network_virtualization_type == VpcVirtualizationType::Fnn
            && vpc.config.vni == Some(configured_vni)
            && vpc.status.vni == Some(configured_vni)
            && !self
                .peerings
                .iter()
                .any(|(left, right)| *left == vpc.id || *right == vpc.id)
            && !self
                .instance_paths
                .iter()
                .any(|path| path.vpc_ids.contains(&vpc.id))
    }

    /// Scans the address inventory once and classifies every overlapping pair.
    ///
    /// Admission and policy checks reuse the returned indices; they remain
    /// valid because neither phase reorders `addresses`. The complete
    /// site-wide comparison is deliberate until
    /// [#3891](https://github.com/NVIDIA/infra-controller/issues/3891) and
    /// [#3892](https://github.com/NVIDIA/infra-controller/issues/3892) replace
    /// the legacy global database exclusions: candidate admission must still
    /// see tolerated direct and same-VPC occupancy. Policy rows are loaded
    /// lazily only after this address phase finds an exact tenant-reuse pair.
    fn analyze_overlaps(&self) -> OverlapAnalysis {
        let mut occupancy_pairs = HashSet::new();
        let mut all_indices = Vec::new();
        let mut tenant_reuse_indices = Vec::new();
        for (left_index, left) in self.addresses.iter().enumerate() {
            for (right_offset, right) in self.addresses[left_index + 1..].iter().enumerate() {
                if !prefixes_overlap(left.prefix, right.prefix) {
                    continue;
                }
                let indices = (left_index, left_index + right_offset + 1);
                all_indices.push(indices);
                if is_tenant_reuse_pair(left, right) {
                    tenant_reuse_indices.push(indices);
                }
                let pair = if left.key < right.key {
                    (left.key, right.key)
                } else {
                    (right.key, left.key)
                };
                occupancy_pairs.insert(pair);
            }
        }
        OverlapAnalysis {
            occupancy_pairs,
            all_indices,
            tenant_reuse_indices,
        }
    }

    /// Validates the SitePrefix association, profile, tenant, CIDR, and VNI of
    /// every reuse pair.
    fn validate_tenant_reuse(
        &self,
        config: &CarbideConfig,
        analysis: &OverlapAnalysis,
    ) -> Result<(), RoutingSafetyFailure> {
        for (left_index, right_index) in &analysis.tenant_reuse_indices {
            let left = &self.addresses[*left_index];
            let right = &self.addresses[*right_index];
            self.validate_overlap_eligibility(config, left, right)?;
        }

        Ok(())
    }

    /// Validates site-wide policy and receiver visibility after reuse is present.
    fn validate_policy_paths(
        &self,
        config: &CarbideConfig,
        analysis: &OverlapAnalysis,
    ) -> Result<(), RoutingSafetyFailure> {
        self.validate_site_policy(config)
            .map_err(|failure| self.with_overlap_context(failure, analysis))?;
        self.validate_active_paths(config)?;
        self.validate_reachability(config, analysis)?;
        Ok(())
    }

    /// Runs both evaluator phases for pure, table-driven policy tests.
    #[cfg(test)]
    fn validate(&self, config: &CarbideConfig) -> Result<(), RoutingSafetyFailure> {
        let analysis = self.analyze_overlaps();
        self.validate_tenant_reuse(config, &analysis)?;
        if analysis.tenant_reuse_indices.is_empty() {
            return Ok(());
        }
        self.validate_policy_paths(config, &analysis)
    }

    /// Attaches one affected pair to a site-wide failure for operator diagnosis.
    fn with_overlap_context(
        &self,
        mut failure: RoutingSafetyFailure,
        analysis: &OverlapAnalysis,
    ) -> RoutingSafetyFailure {
        if let Some((left_index, right_index)) = analysis.tenant_reuse_indices.first() {
            let left = &self.addresses[*left_index];
            let right = &self.addresses[*right_index];
            failure.vpc_ids.extend([left.vpc_id, right.vpc_id]);
            failure
                .resource_ids
                .extend([left.key.to_string(), right.key.to_string()]);
        }
        failure
    }

    /// Checks the complete per-pair contract before policy-path analysis.
    ///
    /// Reuse requires an equal CIDR in separate FNN VPCs and tenants, valid
    /// tenant-managed SitePrefix ownership and containment, overlap-safe base
    /// profiles, and distinct effective VNIs.
    fn validate_overlap_eligibility(
        &self,
        config: &CarbideConfig,
        left: &RoutedAddress,
        right: &RoutedAddress,
    ) -> Result<(), RoutingSafetyFailure> {
        if left.prefix != right.prefix
            || matches!(left.source, AddressSource::Network { .. })
            || matches!(right.source, AddressSource::Network { .. })
        {
            return Err(RoutingSafetyFailure::for_pair(
                RoutingSafetyViolation::IneligibleOverlap,
                "prefixes_not_equal_or_direct",
                left,
                right,
            ));
        }
        let left_vpc = self.vpcs.get(&left.vpc_id).ok_or_else(|| {
            RoutingSafetyFailure::for_pair(
                RoutingSafetyViolation::IneligibleOverlap,
                "missing_vpc",
                left,
                right,
            )
        })?;
        let right_vpc = self.vpcs.get(&right.vpc_id).ok_or_else(|| {
            RoutingSafetyFailure::for_pair(
                RoutingSafetyViolation::IneligibleOverlap,
                "missing_vpc",
                left,
                right,
            )
        })?;
        if left_vpc.config.network_virtualization_type != VpcVirtualizationType::Fnn
            || right_vpc.config.network_virtualization_type != VpcVirtualizationType::Fnn
            || left_vpc.config.tenant_organization_id == right_vpc.config.tenant_organization_id
        {
            return Err(RoutingSafetyFailure::for_pair(
                RoutingSafetyViolation::IneligibleOverlap,
                "vpc_type_or_tenant_ineligible",
                left,
                right,
            ));
        }
        self.validate_vpc_prefix_site_association(left_vpc, left)?;
        self.validate_vpc_prefix_site_association(right_vpc, right)?;
        self.validate_profile(config, left_vpc, profile_allows_overlap)?;
        self.validate_profile(config, right_vpc, profile_allows_overlap)?;

        let left_vni = left_vpc.status.vni.ok_or_else(|| {
            RoutingSafetyFailure::for_vpc(
                RoutingSafetyViolation::UnsafePolicy,
                "missing_vpc_vni",
                left_vpc.id,
            )
        })?;
        let right_vni = right_vpc.status.vni.ok_or_else(|| {
            RoutingSafetyFailure::for_vpc(
                RoutingSafetyViolation::UnsafePolicy,
                "missing_vpc_vni",
                right_vpc.id,
            )
        })?;
        if left_vni == right_vni {
            return Err(RoutingSafetyFailure::for_pair(
                RoutingSafetyViolation::UnsafePolicy,
                "duplicate_vpc_vni",
                left,
                right,
            ));
        }
        Ok(())
    }

    /// Proves that a VPC prefix belongs to a usable tenant-managed SitePrefix.
    fn validate_vpc_prefix_site_association(
        &self,
        vpc: &Vpc,
        address: &RoutedAddress,
    ) -> Result<(), RoutingSafetyFailure> {
        let AddressSource::Vpc { site_prefix_id } = address.source else {
            return Err(RoutingSafetyFailure::for_address(
                RoutingSafetyViolation::IneligibleOverlap,
                "direct_prefix_has_no_site_prefix",
                vpc.id,
                address,
            ));
        };
        let root = site_prefix_id
            .and_then(|id| self.site_prefixes.get(&id).copied())
            .ok_or_else(|| {
                RoutingSafetyFailure::for_address(
                    RoutingSafetyViolation::IneligibleOverlap,
                    "missing_site_prefix",
                    vpc.id,
                    address,
                )
            })?;
        if root.status.authority != SitePrefixAuthority::TenantManaged
            || root.config.routing_scope != SitePrefixRoutingScope::DatacenterOnly
            || !matches!(
                root.status.lifecycle_state,
                SitePrefixLifecycleState::Ready | SitePrefixLifecycleState::Deleting
            )
            || root
                .config
                .tenant_organization_id
                .as_ref()
                .map(|id| id.as_str())
                != Some(vpc.config.tenant_organization_id.as_str())
            || !prefix_contains(root.config.prefix, address.prefix)
        {
            return Err(RoutingSafetyFailure::for_address(
                RoutingSafetyViolation::IneligibleOverlap,
                "invalid_site_prefix_association",
                vpc.id,
                address,
            ));
        }
        Ok(())
    }

    /// Resolves the effective VPC profile and applies the requested safety rule.
    fn validate_profile(
        &self,
        config: &CarbideConfig,
        vpc: &Vpc,
        is_safe: fn(&FnnRoutingProfileConfig) -> bool,
    ) -> Result<(), RoutingSafetyFailure> {
        let profile = config
            .fnn
            .as_ref()
            .ok_or_else(|| {
                RoutingSafetyFailure::for_vpc(
                    RoutingSafetyViolation::UnsafePolicy,
                    "missing_fnn_config",
                    vpc.id,
                )
            })?
            .resolve_vpc_routing_profile(&vpc.config)
            .map_err(|_| {
                RoutingSafetyFailure::for_vpc(
                    RoutingSafetyViolation::UnsafePolicy,
                    "unresolved_vpc_routing_profile",
                    vpc.id,
                )
            })?;
        if is_safe(&profile) {
            Ok(())
        } else {
            Err(RoutingSafetyFailure::for_vpc(
                RoutingSafetyViolation::UnsafePolicy,
                "unsafe_vpc_routing_profile",
                vpc.id,
            ))
        }
    }

    /// Rejects site-wide features that can bridge otherwise isolated VPCs.
    fn validate_site_policy(&self, config: &CarbideConfig) -> Result<(), RoutingSafetyFailure> {
        let fnn = config.fnn.as_ref().ok_or_else(|| {
            RoutingSafetyFailure::new(RoutingSafetyViolation::UnsafePolicy, "missing_fnn_config")
        })?;
        let reason = if config.vpc_isolation_behavior != VpcIsolationBehaviorType::MutualIsolation {
            Some("site_isolation_not_mutual")
        } else if config.site_global_vpc_vni.is_some() {
            Some("site_global_vpc_vni_enabled")
        } else if !config.anycast_site_prefixes.is_empty() {
            Some("site_anycast_prefixes_enabled")
        } else if config.vmaas_config.is_some() {
            Some("vmaas_enabled")
        } else if fnn.common_internal_route_target.is_some() {
            Some("common_internal_route_target_enabled")
        } else if !fnn.additional_route_target_imports.is_empty() {
            Some("additional_route_target_imports_enabled")
        } else if config
            .network_security_group
            .policy_overrides
            .iter()
            .any(|rule| rule.action == NetworkSecurityGroupRuleAction::Permit)
        {
            Some("site_nsg_permit_override_enabled")
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(RoutingSafetyFailure::new(
                RoutingSafetyViolation::UnsafePolicy,
                reason,
            ));
        }
        Ok(())
    }

    /// Checks every graph-active tenant path, not only the VPCs sharing a CIDR.
    ///
    /// The renderer builds one site-wide isolation list, so an unrelated active
    /// path with a permit or leak can invalidate the site's reuse guarantee.
    /// Every active FNN VPC also needs a present, site-unique rendered VNI.
    fn validate_active_paths(&self, config: &CarbideConfig) -> Result<(), RoutingSafetyFailure> {
        let mut active_vpcs = self
            .addresses
            .iter()
            .map(|address| address.vpc_id)
            .collect::<HashSet<_>>();
        if let Some(policy) = config
            .vpc_peering_policy_on_existing
            .or(config.vpc_peering_policy)
        {
            for (vpc_id, peer_vpc_id) in &self.peerings {
                let vpc = self.vpcs.get(vpc_id).ok_or_else(|| {
                    RoutingSafetyFailure::for_vpc(
                        RoutingSafetyViolation::UnsafePolicy,
                        "missing_peered_vpc",
                        *vpc_id,
                    )
                })?;
                let peer_vpc = self.vpcs.get(peer_vpc_id).ok_or_else(|| {
                    RoutingSafetyFailure::for_vpc(
                        RoutingSafetyViolation::UnsafePolicy,
                        "missing_peered_vpc",
                        *peer_vpc_id,
                    )
                    .with_vpc(*vpc_id)
                })?;
                let vpc_type = vpc.config.network_virtualization_type;
                let peer_vpc_type = peer_vpc.config.network_virtualization_type;
                if peering_direction_is_active(policy, vpc_type, peer_vpc_type)
                    || peering_direction_is_active(policy, peer_vpc_type, vpc_type)
                {
                    active_vpcs.insert(*vpc_id);
                    active_vpcs.insert(*peer_vpc_id);
                }
            }
        }
        let mut referenced_groups = HashSet::new();
        for path in &self.instance_paths {
            if path.has_unresolved_reference {
                return Err(RoutingSafetyFailure::new(
                    RoutingSafetyViolation::UnsafePolicy,
                    "unresolved_instance_network_reference",
                )
                .with_resource(format!("instance:{}", path.instance_id)));
            }
            if !path.vpc_ids.is_empty() && path.has_routing_override {
                let mut failure = RoutingSafetyFailure::new(
                    RoutingSafetyViolation::UnsafePolicy,
                    "instance_routing_override_enabled",
                )
                .with_resource(format!("instance:{}", path.instance_id));
                failure.vpc_ids.extend(path.vpc_ids.iter().copied());
                return Err(failure);
            }
            active_vpcs.extend(path.vpc_ids.iter().copied());
            if !path.vpc_ids.is_empty()
                && let Some(group_id) = &path.network_security_group_id
            {
                referenced_groups.insert(group_id.clone());
            }
        }
        let mut active_vpcs = active_vpcs.into_iter().collect::<Vec<_>>();
        active_vpcs.sort();
        let mut active_fnn_vnis = HashMap::new();
        for vpc_id in active_vpcs {
            let vpc = self.vpcs.get(&vpc_id).ok_or_else(|| {
                RoutingSafetyFailure::for_vpc(
                    RoutingSafetyViolation::UnsafePolicy,
                    "missing_active_vpc",
                    vpc_id,
                )
            })?;
            if vpc.config.network_virtualization_type == VpcVirtualizationType::Fnn {
                let vni = vpc.status.vni.ok_or_else(|| {
                    RoutingSafetyFailure::for_vpc(
                        RoutingSafetyViolation::UnsafePolicy,
                        "missing_active_vpc_vni",
                        vpc_id,
                    )
                })?;
                if let Some(other_vpc_id) = active_fnn_vnis.insert(vni, vpc_id) {
                    return Err(RoutingSafetyFailure::for_vpc(
                        RoutingSafetyViolation::UnsafePolicy,
                        "duplicate_active_vpc_vni",
                        vpc_id,
                    )
                    .with_vpc(other_vpc_id));
                }
            }

            let is_admin_control_path = self.is_unconsumed_admin_vpc(config, vpc);
            if !is_admin_control_path
                && vpc.config.network_virtualization_type == VpcVirtualizationType::Fnn
            {
                self.validate_profile(config, vpc, profile_preserves_isolation)?;
            }
            if !is_admin_control_path && let Some(group_id) = &vpc.config.network_security_group_id
            {
                referenced_groups.insert(group_id.clone());
            }
        }
        let mut referenced_groups = referenced_groups.into_iter().collect::<Vec<_>>();
        referenced_groups.sort_by_cached_key(ToString::to_string);
        for group_id in referenced_groups {
            let group = self.network_security_groups.get(&group_id).ok_or_else(|| {
                RoutingSafetyFailure::new(
                    RoutingSafetyViolation::UnsafePolicy,
                    "missing_active_network_security_group",
                )
                .with_resource(format!("network-security-group:{group_id}"))
            })?;
            if !network_security_group_is_safe(group) {
                return Err(RoutingSafetyFailure::new(
                    RoutingSafetyViolation::UnsafePolicy,
                    "unsafe_active_network_security_group",
                )
                .with_resource(format!("network-security-group:{group_id}")));
            }
        }
        Ok(())
    }

    /// Returns every VPC visible to one receiver through direct attachments and peers.
    fn visible_vpcs(
        &self,
        policy: Option<VpcPeeringPolicy>,
        directly_visible: &HashSet<VpcId>,
    ) -> Result<HashSet<VpcId>, RoutingSafetyFailure> {
        let mut visible_vpcs = directly_visible.clone();
        let Some(policy) = policy else {
            return Ok(visible_vpcs);
        };

        for receiver_id in directly_visible {
            let receiver = self.vpcs.get(receiver_id).ok_or_else(|| {
                RoutingSafetyFailure::for_vpc(
                    RoutingSafetyViolation::UnsafePolicy,
                    "missing_active_vpc",
                    *receiver_id,
                )
            })?;
            for (left, right) in &self.peerings {
                let peer_id = if *receiver_id == *left {
                    Some(*right)
                } else if *receiver_id == *right {
                    Some(*left)
                } else {
                    None
                };
                let Some(peer_id) = peer_id else {
                    continue;
                };
                let peer = self.vpcs.get(&peer_id).ok_or_else(|| {
                    RoutingSafetyFailure::for_vpc(
                        RoutingSafetyViolation::UnsafePolicy,
                        "missing_peered_vpc",
                        peer_id,
                    )
                    .with_vpc(*receiver_id)
                })?;
                if peering_direction_is_active(
                    policy,
                    receiver.config.network_virtualization_type,
                    peer.config.network_virtualization_type,
                ) {
                    visible_vpcs.insert(peer_id);
                }
            }
        }
        Ok(visible_vpcs)
    }

    /// Builds the standard failure when one receiver sees both sides of a reuse pair.
    fn visible_overlap_failure(
        &self,
        analysis: &OverlapAnalysis,
        visible_vpcs: &HashSet<VpcId>,
    ) -> Option<RoutingSafetyFailure> {
        analysis
            .tenant_reuse_indices
            .iter()
            .find_map(|(left_index, right_index)| {
                let left = &self.addresses[*left_index];
                let right = &self.addresses[*right_index];
                (visible_vpcs.contains(&left.vpc_id) && visible_vpcs.contains(&right.vpc_id)).then(
                    || {
                        RoutingSafetyFailure::for_pair(
                            RoutingSafetyViolation::ReachableOverlap,
                            "receiver_sees_overlapping_address_space",
                            left,
                            right,
                        )
                    },
                )
            })
    }

    /// Rejects a VPC or retained instance receiver that can see both reused prefixes.
    ///
    /// VPC receivers cover direct and sibling peer imports. Instance receivers
    /// additionally union every attached VPC and each attachment's direct peers.
    fn validate_reachability(
        &self,
        config: &CarbideConfig,
        analysis: &OverlapAnalysis,
    ) -> Result<(), RoutingSafetyFailure> {
        let policy = config
            .vpc_peering_policy_on_existing
            .or(config.vpc_peering_policy);
        if policy.is_some() {
            let mut receivers = self.vpcs.values().copied().collect::<Vec<_>>();
            receivers.sort_by_key(|vpc| vpc.id);
            for receiver in receivers {
                let directly_visible = HashSet::from([receiver.id]);
                let visible_vpcs = self.visible_vpcs(policy, &directly_visible)?;
                if let Some(failure) = self.visible_overlap_failure(analysis, &visible_vpcs) {
                    return Err(failure.with_vpc(receiver.id));
                }
            }
        }

        // An instance receives the union of every attached VPC interface. Each
        // interface can also import its VPC's direct peers, so no individual
        // VPC receiver need see both reused prefixes for the host to see both.
        for path in &self.instance_paths {
            let visible_vpcs = self.visible_vpcs(policy, &path.vpc_ids)?;
            if let Some(failure) = self.visible_overlap_failure(analysis, &visible_vpcs) {
                return Err(failure.with_resource(format!("instance:{}", path.instance_id)));
            }
        }
        Ok(())
    }
}

/// Merges one retained network config into an instance's routing dependencies.
///
/// An existing unbound segment is acceptable when the interface supplies its
/// logical VPC explicitly. Missing rows remain unresolved so deletion and
/// update races cannot silently remove a policy constraint.
fn collect_instance_path(
    config: &InstanceNetworkConfig,
    segment_vpcs: &HashMap<NetworkSegmentId, Option<VpcId>>,
    vpc_prefix_vpcs: &HashMap<VpcPrefixId, VpcId>,
    vpc_ids: &mut HashSet<VpcId>,
    has_routing_override: &mut bool,
    has_unresolved_reference: &mut bool,
) {
    if let Some(auto) = config.auto_config {
        vpc_ids.insert(auto.vpc_id);
    }
    for interface in &config.interfaces {
        let logical_vpc_id = interface
            .vpc_id
            .or_else(|| interface.vpc_selection.map(|selection| selection.vpc_id))
            .or(config.auto_config.map(|auto| auto.vpc_id));
        if let Some(vpc_id) = logical_vpc_id {
            vpc_ids.insert(vpc_id);
        }
        if let Some(segment_id) = interface.network_segment_id {
            collect_segment_vpc(
                segment_id,
                logical_vpc_id,
                segment_vpcs,
                vpc_ids,
                has_unresolved_reference,
            );
        }
        match interface.network_details {
            Some(NetworkDetails::NetworkSegment(segment_id)) => {
                collect_segment_vpc(
                    segment_id,
                    logical_vpc_id,
                    segment_vpcs,
                    vpc_ids,
                    has_unresolved_reference,
                );
            }
            Some(NetworkDetails::VpcPrefixId(vpc_prefix_id)) => {
                match vpc_prefix_vpcs.get(&vpc_prefix_id) {
                    Some(vpc_id) => {
                        vpc_ids.insert(*vpc_id);
                    }
                    None => *has_unresolved_reference = true,
                }
            }
            None => {}
        }
        if let Some(ipv6) = &interface.ipv6_interface_config {
            match vpc_prefix_vpcs.get(&ipv6.vpc_prefix_id) {
                Some(vpc_id) => {
                    vpc_ids.insert(*vpc_id);
                }
                None => *has_unresolved_reference = true,
            }
        }
        if let Some(InstanceInterfaceRoutingProfile {
            allowed_anycast_prefixes,
        }) = interface.routing_profile.as_ref()
        {
            *has_routing_override |= !allowed_anycast_prefixes.is_empty();
        }
    }
}

/// Resolves one retained segment reference without treating a valid unbound
/// HostInband segment as missing when the interface records its logical VPC.
fn collect_segment_vpc(
    segment_id: NetworkSegmentId,
    logical_vpc_id: Option<VpcId>,
    segment_vpcs: &HashMap<NetworkSegmentId, Option<VpcId>>,
    vpc_ids: &mut HashSet<VpcId>,
    has_unresolved_reference: &mut bool,
) {
    match segment_vpcs.get(&segment_id) {
        Some(Some(vpc_id)) => {
            vpc_ids.insert(*vpc_id);
        }
        Some(None) if logical_vpc_id.is_some() => {}
        Some(None) | None => *has_unresolved_reference = true,
    }
}

/// Returns whether the renderer imports anything from `peer_type` into `receiver_type`.
///
/// A configured `None` policy disables prefix imports but retains capability-driven
/// VNI imports. The caller handles the distinct case where both policy options are unset.
fn peering_direction_is_active(
    policy: VpcPeeringPolicy,
    receiver_type: VpcVirtualizationType,
    peer_type: VpcVirtualizationType,
) -> bool {
    let imports_peer_prefixes = match policy {
        VpcPeeringPolicy::Exclusive => receiver_type.capabilities().peers_with.contains(&peer_type),
        VpcPeeringPolicy::Mixed => true,
        VpcPeeringPolicy::None => false,
    };
    let imports_peer_vni =
        receiver_type.imports_peer_vnis_into_overlay() && peer_type.vni_advertised_to_peers();
    imports_peer_prefixes || imports_peer_vni
}

/// Returns whether an effective FNN profile may participate in tenant overlap.
fn profile_allows_overlap(profile: &FnnRoutingProfileConfig) -> bool {
    profile.overlap_eligible && profile_preserves_isolation(profile)
}

/// Returns whether an effective FNN profile keeps its VPC routing domain private.
///
/// This is an explicit allowlist. Every new profile field that can introduce
/// reachability must be considered here before it is safe for reuse.
fn profile_preserves_isolation(profile: &FnnRoutingProfileConfig) -> bool {
    let FnnRoutingProfileConfig {
        // This flag controls overlap admission and does not alter rendered routes.
        overlap_eligible: _,
        route_target_imports,
        route_targets_on_exports,
        internal,
        leak_default_route_from_underlay,
        leak_tenant_host_routes_to_underlay,
        tenant_leak_communities_accepted,
        accepted_leaks_from_underlay,
        allowed_anycast_prefixes,
        // Access tier controls who can select a profile, not the routes it renders.
        access_tier: _,
    } = profile;

    *internal == Some(true)
        && route_target_imports.as_ref().is_none_or(Vec::is_empty)
        && route_targets_on_exports.as_ref().is_none_or(Vec::is_empty)
        && !leak_default_route_from_underlay.unwrap_or_default()
        && !leak_tenant_host_routes_to_underlay.unwrap_or_default()
        && !tenant_leak_communities_accepted.unwrap_or_default()
        && accepted_leaks_from_underlay
            .as_ref()
            .is_none_or(Vec::is_empty)
        && allowed_anycast_prefixes.as_ref().is_none_or(Vec::is_empty)
}

/// Returns whether an NSG can only remove, rather than introduce, reachability.
fn network_security_group_is_safe(group: &NetworkSecurityGroup) -> bool {
    !group.stateful_egress
        && group
            .rules
            .iter()
            .all(|rule| rule.action == NetworkSecurityGroupRuleAction::Deny)
}

fn prefixes_overlap(left: IpNetwork, right: IpNetwork) -> bool {
    left.is_ipv4() == right.is_ipv4()
        && (left.contains(right.network()) || right.contains(left.network()))
}

/// Classifies the only overlap case that may proceed to eligibility checks.
///
/// This proves neither tenant ownership nor isolation; those checks deliberately
/// remain in `validate_overlap_eligibility` and the policy phase.
fn is_tenant_reuse_pair(left: &RoutedAddress, right: &RoutedAddress) -> bool {
    left.vpc_id != right.vpc_id
        && left.prefix == right.prefix
        && matches!(left.source, AddressSource::Vpc { .. })
        && matches!(right.source, AddressSource::Vpc { .. })
}

fn prefix_contains(parent: IpNetwork, child: IpNetwork) -> bool {
    parent.is_ipv4() == child.is_ipv4()
        && parent.prefix() <= child.prefix()
        && parent.contains(child.network())
}

/// Stable violation categories used to classify privacy-safe client errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
enum RoutingSafetyViolation {
    /// A candidate introduces overlap while the site opt-in is disabled.
    #[error("{OVERLAPPING_ADDRESS_SPACE}")]
    OverlapDisabled,
    /// A candidate introduces address occupancy that is not tenant reuse.
    #[error("{OVERLAPPING_ADDRESS_SPACE}")]
    AddressConflict,
    /// An exact reuse pair fails its SitePrefix association or isolation prerequisites.
    #[error("{INELIGIBLE_OVERLAP}")]
    IneligibleOverlap,
    /// A route receiver would import both copies of reused address space.
    #[error("{REACHABLE_OVERLAP}")]
    ReachableOverlap,
    /// A VNI, site, profile, NSG, or retained-instance condition cannot prove isolation.
    #[error("{UNSAFE_POLICY}")]
    UnsafePolicy,
}

impl RoutingSafetyViolation {
    fn code(self) -> &'static str {
        match self {
            Self::OverlapDisabled => "overlap_disabled",
            Self::AddressConflict => "address_conflict",
            Self::IneligibleOverlap => "ineligible_overlap",
            Self::ReachableOverlap => "reachable_overlap",
            Self::UnsafePolicy => "unsafe_policy",
        }
    }
}

/// Internal diagnostic for one rejected admission decision.
///
/// `reason` and resource identifiers are logged for operators but are never
/// copied into the client response, where foreign tenant details would leak.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RoutingSafetyFailure {
    violation: RoutingSafetyViolation,
    reason: &'static str,
    vpc_ids: Vec<VpcId>,
    resource_ids: Vec<String>,
}

impl RoutingSafetyFailure {
    fn new(violation: RoutingSafetyViolation, reason: &'static str) -> Self {
        Self {
            violation,
            reason,
            vpc_ids: Vec::new(),
            resource_ids: Vec::new(),
        }
    }

    fn for_vpc(violation: RoutingSafetyViolation, reason: &'static str, vpc_id: VpcId) -> Self {
        Self {
            vpc_ids: vec![vpc_id],
            ..Self::new(violation, reason)
        }
    }

    fn for_address(
        violation: RoutingSafetyViolation,
        reason: &'static str,
        vpc_id: VpcId,
        address: &RoutedAddress,
    ) -> Self {
        Self {
            vpc_ids: vec![vpc_id],
            resource_ids: vec![address.key.to_string()],
            ..Self::new(violation, reason)
        }
    }

    fn for_pair(
        violation: RoutingSafetyViolation,
        reason: &'static str,
        left: &RoutedAddress,
        right: &RoutedAddress,
    ) -> Self {
        Self {
            vpc_ids: vec![left.vpc_id, right.vpc_id],
            resource_ids: vec![left.key.to_string(), right.key.to_string()],
            ..Self::new(violation, reason)
        }
    }

    fn with_vpc(mut self, vpc_id: VpcId) -> Self {
        self.vpc_ids.push(vpc_id);
        self
    }

    fn with_resource(mut self, resource_id: String) -> Self {
        self.resource_ids.push(resource_id);
        self
    }

    /// Logs the private diagnostic context at the boundary that rejects a write.
    fn log(&self, operation: &'static str) {
        let mut vpc_ids = self.vpc_ids.clone();
        vpc_ids.sort();
        vpc_ids.dedup();
        let mut resource_ids = self.resource_ids.clone();
        resource_ids.sort();
        resource_ids.dedup();
        tracing::warn!(
            operation,
            violation = self.violation.code(),
            reason = self.reason,
            vpc_ids = ?vpc_ids,
            resource_ids = ?resource_ids,
            "routing safety validation rejected state"
        );
    }
}

// Keep foreign resource IDs and internal reasons in `RoutingSafetyFailure`.
// Tenant-facing conversion intentionally collapses them into stable messages.
impl From<RoutingSafetyViolation> for CarbideError {
    fn from(error: RoutingSafetyViolation) -> Self {
        match error {
            RoutingSafetyViolation::OverlapDisabled | RoutingSafetyViolation::AddressConflict => {
                CarbideError::InvalidArgument(OVERLAPPING_ADDRESS_SPACE.to_string())
            }
            RoutingSafetyViolation::IneligibleOverlap
            | RoutingSafetyViolation::ReachableOverlap
            | RoutingSafetyViolation::UnsafePolicy => {
                CarbideError::FailedPrecondition(error.to_string())
            }
        }
    }
}

impl From<RoutingSafetyFailure> for CarbideError {
    fn from(error: RoutingSafetyFailure) -> Self {
        error.violation.into()
    }
}

/// `lock_site_mutation` acquires the routing-safety lock before any
/// resource-specific row lock.
///
/// The lock intentionally waits instead of treating ordinary writer
/// contention as an admission failure. The wait follows the caller's request
/// or controller-task lifecycle, and PostgreSQL releases the lock when the
/// owning transaction commits or rolls back.
pub(crate) async fn lock_site_mutation(txn: &mut PgConnection) -> CarbideResult<()> {
    db::routing_safety::lock_site_mutation(txn)
        .await
        .map_err(Into::into)
}

/// `validate_live_state` validates all transaction-visible persisted routing state.
///
/// Callers use it after a transactional policy or graph mutation and before
/// committing it, while they still hold the site mutation lock.
pub(crate) async fn validate_live_state(
    config: &CarbideConfig,
    txn: &mut PgConnection,
) -> CarbideResult<()> {
    validate_persisted_state(config, txn, "routing_mutation").await
}

/// Runs shared startup and post-mutation validation over transaction-visible rows.
///
/// The address phase runs first. Policy rows are fetched only when an exact
/// VPC-prefix reuse pair exists.
async fn validate_persisted_state(
    config: &CarbideConfig,
    txn: &mut PgConnection,
    operation: &'static str,
) -> CarbideResult<()> {
    let addresses = db::routing_safety::load_addresses(txn).await?;
    let mut state = RoutingState::from_addresses(&addresses);
    let analysis = state.analyze_overlaps();
    state
        .validate_tenant_reuse(config, &analysis)
        .map_err(|failure| {
            failure.log(operation);
            CarbideError::from(failure)
        })?;
    if analysis.tenant_reuse_indices.is_empty() {
        return Ok(());
    }

    let policy = db::routing_safety::load_policy_paths(txn).await?;
    state.apply_policy_paths(&policy, &addresses);
    state
        .validate_policy_paths(config, &analysis)
        .map_err(|failure| {
            failure.log(operation);
            failure.into()
        })
}

/// `validate_startup` fails before controllers or listeners can serve a graph
/// that already violates overlap isolation. A latent unsafe profile is
/// harmless until an overlapping route is present, so the evaluator
/// deliberately short-circuits when the live graph has no exact cross-VPC
/// VPC-prefix pair.
pub(crate) async fn validate_startup(
    config: &CarbideConfig,
    pool: &sqlx::PgPool,
) -> CarbideResult<()> {
    let mut txn = db::Transaction::begin(pool).await?;
    lock_site_mutation(&mut txn).await?;
    validate_persisted_state(config, &mut txn, "startup_preflight").await?;
    txn.commit().await?;
    Ok(())
}

/// `validate_vpc_prefix_candidate` checks an insertion before the legacy
/// physical-overlap constraint runs. Adopted network prefixes are removed from
/// the candidate view because the same transaction will attach them to the new
/// parent.
pub(crate) async fn validate_vpc_prefix_candidate(
    config: &CarbideConfig,
    txn: &mut PgConnection,
    candidate: &NewVpcPrefix,
    adopted_network_prefix_ids: &[NetworkPrefixId],
) -> CarbideResult<()> {
    let addresses = db::routing_safety::load_addresses(txn).await?;
    let current = RoutingState::from_addresses(&addresses);
    let current_overlap_pairs = current.analyze_overlaps().occupancy_pairs;
    let mut proposed = RoutingState::from_addresses(&addresses);
    proposed.addresses.retain(|address| {
        !matches!(
            address.source,
            AddressSource::Network { id: Some(id) }
                if adopted_network_prefix_ids.contains(&id)
        )
    });
    proposed.addresses.push(RoutedAddress {
        key: AddressKey::CandidateVpc(candidate.id),
        vpc_id: candidate.vpc_id,
        prefix: candidate.config.prefix,
        source: AddressSource::Vpc {
            site_prefix_id: candidate.site_prefix_id,
        },
    });
    validate_candidate(
        config,
        txn,
        &addresses,
        current_overlap_pairs,
        &mut proposed,
        "vpc_prefix_candidate",
    )
    .await
}

/// `validate_network_segment_candidate` checks a segment before its legacy
/// physical-overlap constraint runs.
pub(crate) async fn validate_network_segment_candidate(
    config: &CarbideConfig,
    txn: &mut PgConnection,
    candidate: &NewNetworkSegment,
) -> CarbideResult<()> {
    let Some(vpc_id) = candidate.vpc_id else {
        return Ok(());
    };
    let prefixes = candidate
        .prefixes
        .iter()
        .map(|prefix| prefix.prefix)
        .collect::<Vec<_>>();
    validate_network_prefix_candidates(config, txn, vpc_id, &prefixes).await
}

/// Checks the address-space effect of binding an existing segment to a VPC.
///
/// An unbound segment is absent from the routed snapshot, while replacement
/// changes the routing classification of every existing pair that contains its
/// prefixes. The simulated snapshot therefore exposes the target VPC to both
/// address and retained-instance resolution before classifying the candidate
/// relationships.
pub(crate) async fn validate_network_segment_attachment(
    config: &CarbideConfig,
    txn: &mut PgConnection,
    candidate: &NetworkSegment,
    vpc_id: VpcId,
) -> CarbideResult<()> {
    let direct_prefixes = candidate
        .prefixes
        .iter()
        .filter(|prefix| prefix.vpc_prefix_id.is_none())
        .collect::<Vec<_>>();
    let moved_keys = direct_prefixes
        .iter()
        .map(|prefix| AddressKey::Network(prefix.id))
        .collect::<HashSet<_>>();
    let mut addresses = db::routing_safety::load_addresses(txn).await?;
    let current = RoutingState::from_addresses(&addresses);
    let mut current_overlap_pairs = current.analyze_overlaps().occupancy_pairs;
    current_overlap_pairs
        .retain(|(left, right)| !moved_keys.contains(left) && !moved_keys.contains(right));

    let simulated_segment = addresses
        .network_segments
        .iter_mut()
        .find(|segment| segment.id == candidate.id)
        .ok_or_else(|| {
            CarbideError::internal(format!(
                "network segment {} is missing from the routing snapshot",
                candidate.id
            ))
        })?;
    simulated_segment.config.vpc_id = Some(vpc_id);
    let mut proposed = RoutingState::from_addresses(&addresses);
    validate_candidate(
        config,
        txn,
        &addresses,
        current_overlap_pairs,
        &mut proposed,
        "network_segment_attachment",
    )
    .await
}

/// Adds direct prefixes to a candidate view without mutating persisted rows.
async fn validate_network_prefix_candidates(
    config: &CarbideConfig,
    txn: &mut PgConnection,
    vpc_id: VpcId,
    prefixes: &[IpNetwork],
) -> CarbideResult<()> {
    let addresses = db::routing_safety::load_addresses(txn).await?;
    let current = RoutingState::from_addresses(&addresses);
    let current_overlap_pairs = current.analyze_overlaps().occupancy_pairs;
    let mut proposed = RoutingState::from_addresses(&addresses);
    proposed.addresses.extend(
        prefixes
            .iter()
            .enumerate()
            .map(|(index, prefix)| RoutedAddress {
                key: AddressKey::CandidateNetwork(index),
                vpc_id,
                prefix: *prefix,
                source: AddressSource::Network { id: None },
            }),
    );
    validate_candidate(
        config,
        txn,
        &addresses,
        current_overlap_pairs,
        &mut proposed,
        "network_prefix_candidate",
    )
    .await
}

/// Rejects only newly introduced occupancy, then loads policy rows if needed.
async fn validate_candidate(
    config: &CarbideConfig,
    txn: &mut PgConnection,
    addresses: &db::routing_safety::RoutingAddressSnapshot,
    current_overlap_pairs: HashSet<(AddressKey, AddressKey)>,
    proposed: &mut RoutingState<'_>,
    operation: &'static str,
) -> CarbideResult<()> {
    let analysis = proposed.analyze_overlaps();
    validate_candidate_addresses(config, &current_overlap_pairs, proposed, &analysis).map_err(
        |failure| {
            failure.log(operation);
            CarbideError::from(failure)
        },
    )?;
    if analysis.tenant_reuse_indices.is_empty() {
        return Ok(());
    }
    let policy = db::routing_safety::load_policy_paths(txn).await?;
    proposed.apply_policy_paths(&policy, addresses);
    proposed
        .validate_policy_paths(config, &analysis)
        .map_err(|failure| {
            failure.log(operation);
            failure.into()
        })
}

/// Compares current and proposed pair identities to distinguish drain from expansion.
///
/// Existing occupancy may contract, but every new pair is classified. With
/// the site gate disabled this freezes expansion without invalidating retained,
/// safely isolated tenant reuse.
fn validate_candidate_addresses(
    config: &CarbideConfig,
    current_overlap_pairs: &HashSet<(AddressKey, AddressKey)>,
    proposed: &RoutingState<'_>,
    analysis: &OverlapAnalysis,
) -> Result<(), RoutingSafetyFailure> {
    if !config.tenant_prefix_overlap_enabled
        && !analysis.occupancy_pairs.is_subset(current_overlap_pairs)
    {
        let mut failure = RoutingSafetyFailure::new(
            RoutingSafetyViolation::OverlapDisabled,
            "site_overlap_gate_disabled",
        );
        if let Some((left, right)) = analysis
            .occupancy_pairs
            .difference(current_overlap_pairs)
            .min()
        {
            failure
                .resource_ids
                .extend([left.to_string(), right.to_string()]);
        }
        return Err(failure);
    }

    for (left_index, right_index) in &analysis.all_indices {
        let left = &proposed.addresses[*left_index];
        let right = &proposed.addresses[*right_index];
        let pair = if left.key < right.key {
            (left.key, right.key)
        } else {
            (right.key, left.key)
        };
        if current_overlap_pairs.contains(&pair) {
            continue;
        }
        // Tenant-reuse pairs are deferred to the full eligibility and policy
        // validation below rather than exempted from candidate admission.
        if is_tenant_reuse_pair(left, right) {
            continue;
        }
        let reason = if left.vpc_id == right.vpc_id {
            "same_vpc_address_conflict"
        } else {
            "address_conflict_not_tenant_reuse"
        };
        return Err(RoutingSafetyFailure::for_pair(
            RoutingSafetyViolation::AddressConflict,
            reason,
            left,
            right,
        ));
    }

    proposed.validate_tenant_reuse(config, analysis)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::time::Duration;

    use carbide_uuid::instance::InstanceId;
    use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
    use carbide_uuid::network::NetworkSegmentId;
    use carbide_uuid::network_security_group::NetworkSecurityGroupId;
    use chrono::Utc;
    use config_version::{ConfigVersion, Versioned};
    use model::instance::config::network::{
        InstanceNetworkAutoConfig, InstanceNetworkConfig, InstanceNetworkConfigUpdate,
    };
    use model::metadata::Metadata;
    use model::network_prefix::NewNetworkPrefix;
    use model::network_security_group::{
        NetworkSecurityGroupRule, NetworkSecurityGroupRuleDirection, NetworkSecurityGroupRuleNet,
        NetworkSecurityGroupRuleProtocol,
    };
    use model::network_segment::{
        AllocationStrategy, NetworkSegment, NetworkSegmentConfig, NetworkSegmentControllerState,
        NetworkSegmentStatus,
    };
    use model::site_prefix::{SitePrefixConfig, SitePrefixStatus};
    use model::tenant::TenantOrganizationId;
    use model::vpc::{
        ALL_VPC_VIRTUALIZATION_TYPES, PrefixFilterPolicyEntry, RouteTargetConfig, VpcConfig,
        VpcStatus,
    };
    use model::vpc_prefix::{
        VpcPrefix, VpcPrefixConfig, VpcPrefixControllerState, VpcPrefixStatus,
    };
    use sqlx::PgPool;

    use super::*;

    const ISOLATED_PROFILE: &str = "ISOLATED";
    const PROFILE: &str = "OVERLAP";
    const UNSAFE_PROFILE: &str = "UNSAFE";

    fn config() -> CarbideConfig {
        let mut config = crate::test_support::default_config::get();
        config.tenant_prefix_overlap_enabled = true;
        config.vmaas_config = None;
        config.fnn = Some(crate::cfg::file::FnnConfig {
            admin_vpc: None,
            common_internal_route_target: None,
            additional_route_target_imports: vec![],
            routing_profiles: HashMap::from([
                (
                    ISOLATED_PROFILE.to_string(),
                    FnnRoutingProfileConfig {
                        overlap_eligible: false,
                        internal: Some(true),
                        ..FnnRoutingProfileConfig::default()
                    },
                ),
                (
                    PROFILE.to_string(),
                    FnnRoutingProfileConfig {
                        overlap_eligible: true,
                        internal: Some(true),
                        ..FnnRoutingProfileConfig::default()
                    },
                ),
                (
                    UNSAFE_PROFILE.to_string(),
                    FnnRoutingProfileConfig {
                        overlap_eligible: true,
                        internal: Some(false),
                        ..FnnRoutingProfileConfig::default()
                    },
                ),
            ]),
            use_vpc_vrf_loopback: false,
        });
        config
    }

    fn vpc(tenant: &str, profile: &str, vni: i32) -> Vpc {
        let now = Utc::now();
        Vpc {
            id: VpcId::new(),
            version: ConfigVersion::initial(),
            config: VpcConfig {
                tenant_organization_id: tenant.to_string(),
                tenant_keyset_id: None,
                network_virtualization_type: VpcVirtualizationType::Fnn,
                network_security_group_id: None,
                default_nvlink_logical_partition_id: None,
                vni: Some(vni),
                routing_profile_type: Some(profile.to_string()),
                routing_profile_overrides: None,
                power_resource_group: None,
            },
            status: VpcStatus { vni: Some(vni) },
            metadata: Metadata::default(),
            created: now,
            updated: now,
            deleted: None,
        }
    }

    fn site_prefix(tenant: &str, prefix: &str) -> SitePrefix {
        let now = Utc::now();
        SitePrefix {
            id: SitePrefixId::new(),
            config: SitePrefixConfig {
                prefix: prefix.parse().unwrap(),
                tenant_organization_id: Some(TenantOrganizationId::from_str(tenant).unwrap()),
                routing_scope: SitePrefixRoutingScope::DatacenterOnly,
            },
            metadata: Metadata::default(),
            status: SitePrefixStatus {
                authority: SitePrefixAuthority::TenantManaged,
                lifecycle_state: SitePrefixLifecycleState::Ready,
            },
            version: ConfigVersion::initial(),
            created_at: now,
            updated_at: now,
        }
    }

    fn address(key: usize, vpc: &Vpc, root: &SitePrefix, prefix: &str) -> RoutedAddress {
        RoutedAddress {
            key: AddressKey::Vpc(VpcPrefixId::from(uuid::Uuid::from_u128(key as u128))),
            vpc_id: vpc.id,
            prefix: prefix.parse().unwrap(),
            source: AddressSource::Vpc {
                site_prefix_id: Some(root.id),
            },
        }
    }

    #[test]
    fn address_keys_preserve_namespace_order_and_rendering() {
        let network_prefix_id = NetworkPrefixId::new();
        let vpc_prefix_id = VpcPrefixId::new();
        let keys = [
            AddressKey::CandidateNetwork(7),
            AddressKey::CandidateVpc(vpc_prefix_id),
            AddressKey::Network(network_prefix_id),
            AddressKey::Vpc(vpc_prefix_id),
        ];

        assert!(keys.is_sorted());
        assert_eq!(
            keys.map(|key| key.to_string()),
            [
                "candidate-network-prefix:7".to_string(),
                format!("candidate-vpc-prefix:{vpc_prefix_id}"),
                format!("network-prefix:{network_prefix_id}"),
                format!("vpc-prefix:{vpc_prefix_id}"),
            ]
        );
    }

    fn vpc_prefix(vpc: &Vpc, root: &SitePrefix, prefix: &str) -> VpcPrefix {
        VpcPrefix {
            id: VpcPrefixId::new(),
            site_prefix_id: Some(root.id),
            vpc_id: vpc.id,
            config: VpcPrefixConfig {
                prefix: prefix.parse().unwrap(),
            },
            metadata: Metadata::default(),
            status: VpcPrefixStatus {
                controller_state: Versioned::new(
                    VpcPrefixControllerState::Ready,
                    ConfigVersion::initial(),
                ),
                controller_state_outcome: None,
                last_used_prefix: None,
                total_31_segments: 0,
                available_31_segments: 0,
                total_linknet_segments: 0,
                available_linknet_segments: 0,
            },
            deleted: None,
        }
    }

    fn unbound_host_inband_segment(id: NetworkSegmentId) -> NetworkSegment {
        let now = Utc::now();
        NetworkSegment {
            id,
            version: ConfigVersion::initial(),
            config: NetworkSegmentConfig {
                name: "unbound-host-inband".to_string(),
                subdomain_id: None,
                mtu: 1500,
                segment_type: NetworkSegmentType::HostInband,
                allocation_strategy: AllocationStrategy::Dynamic,
                infer_slaac_eui64_addresses: false,
                vpc_id: None,
            },
            status: NetworkSegmentStatus {
                controller_state: Versioned::new(
                    NetworkSegmentControllerState::Ready,
                    ConfigVersion::initial(),
                ),
                controller_state_outcome: None,
                history: Vec::new(),
                vlan_id: None,
                vni: None,
                can_stretch: None,
            },
            prefixes: Vec::new(),
            created: now,
            updated: now,
            deleted: None,
        }
    }

    fn bound_segment(vpc_id: VpcId, segment_type: NetworkSegmentType) -> NetworkSegment {
        let mut segment = unbound_host_inband_segment(NetworkSegmentId::new());
        segment.config.name = "bound-routing-safety-test".to_string();
        segment.config.segment_type = segment_type;
        segment.config.vpc_id = Some(vpc_id);
        segment
    }

    fn state<'a>(
        vpcs: &'a [Vpc],
        roots: &'a [SitePrefix],
        addresses: Vec<RoutedAddress>,
    ) -> RoutingState<'a> {
        RoutingState {
            vpcs: vpcs.iter().map(|vpc| (vpc.id, vpc)).collect(),
            site_prefixes: roots.iter().map(|root| (root.id, root)).collect(),
            addresses,
            admin_only_vpcs: HashSet::new(),
            peerings: vec![],
            network_security_groups: HashMap::new(),
            instance_paths: vec![],
        }
    }

    fn overlapping_state<'a>(vpcs: &'a [Vpc], roots: &'a [SitePrefix]) -> RoutingState<'a> {
        state(
            vpcs,
            roots,
            vec![
                address(0, &vpcs[0], &roots[0], "10.0.0.0/24"),
                address(1, &vpcs[1], &roots[1], "10.0.0.0/24"),
            ],
        )
    }

    fn instance_path(vpc_ids: impl IntoIterator<Item = VpcId>) -> InstancePath {
        InstancePath {
            instance_id: InstanceId::new(),
            vpc_ids: vpc_ids.into_iter().collect(),
            network_security_group_id: None,
            has_routing_override: false,
            has_unresolved_reference: false,
        }
    }

    fn security_group_rule(action: NetworkSecurityGroupRuleAction) -> NetworkSecurityGroupRule {
        NetworkSecurityGroupRule {
            id: None,
            src_net: NetworkSecurityGroupRuleNet::Prefix("0.0.0.0/0".parse().unwrap()),
            dst_net: NetworkSecurityGroupRuleNet::Prefix("0.0.0.0/0".parse().unwrap()),
            direction: NetworkSecurityGroupRuleDirection::Ingress,
            ipv6: false,
            src_port_start: None,
            src_port_end: None,
            dst_port_start: None,
            dst_port_end: None,
            protocol: NetworkSecurityGroupRuleProtocol::Any,
            action,
            priority: 1,
        }
    }

    fn network_security_group(
        id: NetworkSecurityGroupId,
        tenant: &str,
        stateful_egress: bool,
        rules: Vec<NetworkSecurityGroupRule>,
    ) -> NetworkSecurityGroup {
        NetworkSecurityGroup {
            id,
            tenant_organization_id: TenantOrganizationId::from_str(tenant).unwrap(),
            stateful_egress,
            rules,
            version: ConfigVersion::initial(),
            created: Utc::now(),
            deleted: None,
            metadata: Metadata::default(),
            created_by: None,
            updated_by: None,
        }
    }

    fn violation(result: Result<(), RoutingSafetyFailure>) -> Result<(), RoutingSafetyViolation> {
        result.map_err(|failure| failure.violation)
    }

    fn new_vpc_prefix(
        id: VpcPrefixId,
        vpc_id: VpcId,
        site_prefix_id: SitePrefixId,
        prefix: IpNetwork,
    ) -> NewVpcPrefix {
        NewVpcPrefix {
            id,
            site_prefix_id: Some(site_prefix_id),
            vpc_id,
            config: VpcPrefixConfig { prefix },
            metadata: Metadata::default(),
        }
    }

    #[crate::sqlx_test]
    async fn no_overlap_validation_skips_policy_projection(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let machine_id = MachineId::new(
            MachineIdSource::ProductBoardChassisSerial,
            [0x3a; 32],
            MachineType::Host,
        );
        let mut setup = pool.begin().await?;
        sqlx::query(
            "INSERT INTO tenants (organization_id, organization_name, version) \
             VALUES ('tenant-a', 'Tenant A', $1)",
        )
        .bind(ConfigVersion::initial())
        .execute(setup.as_mut())
        .await?;
        sqlx::query("INSERT INTO machines (id, dpf) VALUES ($1, '{}'::jsonb)")
            .bind(machine_id)
            .execute(setup.as_mut())
            .await?;
        sqlx::query(
            "INSERT INTO instances \
             (machine_id, tenant_org, os_ipxe_script, network_config, nvlink_config) \
             VALUES ($1, 'tenant-a', '#!ipxe invalid-routing-projection', \
                     '{\"invalid\": true}'::jsonb, '{\"gpu_configs\": []}'::jsonb)",
        )
        .bind(machine_id)
        .execute(setup.as_mut())
        .await?;
        setup.commit().await?;

        let mut validation = pool.begin().await?;
        lock_site_mutation(validation.as_mut()).await?;
        validate_live_state(&config(), validation.as_mut()).await?;
        validation.commit().await?;

        let mut proof = pool.begin().await?;
        assert!(
            db::routing_safety::load_policy_paths(proof.as_mut())
                .await
                .is_err(),
            "the invalid instance row proves the no-overlap path did not hydrate policy rows"
        );
        proof.rollback().await?;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn startup_accepts_legacy_direct_prefix_containment(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let same_vpc_id = VpcId::new();
        let tenant_vpc_id = VpcId::new();
        let admin_vpc_id = VpcId::new();
        let version = ConfigVersion::initial();
        let mut setup = pool.begin().await?;

        for (vpc_id, name, organization_id) in [
            (same_vpc_id, "same-vpc-legacy", "tenant-a"),
            (tenant_vpc_id, "tenant-prefix-legacy", "tenant-b"),
            (admin_vpc_id, "admin-segment-legacy", "carbide_internal"),
        ] {
            sqlx::query(
                "INSERT INTO vpcs (id, name, organization_id, version) VALUES ($1, $2, $3, $4)",
            )
            .bind(vpc_id)
            .bind(name)
            .bind(organization_id)
            .bind(version)
            .execute(setup.as_mut())
            .await?;
        }

        for (id, vpc_id, name, prefix) in [
            (
                VpcPrefixId::new(),
                same_vpc_id,
                "same-vpc-parent",
                "10.70.0.0/24".parse::<IpNetwork>()?,
            ),
            (
                VpcPrefixId::new(),
                tenant_vpc_id,
                "admin-contained-prefix",
                "192.0.2.128/25".parse::<IpNetwork>()?,
            ),
        ] {
            sqlx::query(
                "INSERT INTO network_vpc_prefixes (id, prefix, name, vpc_id) \
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(id)
            .bind(prefix)
            .bind(name)
            .bind(vpc_id)
            .execute(setup.as_mut())
            .await?;
        }

        for (name, vpc_id, segment_type, prefix) in [
            (
                "same-vpc-direct-child",
                same_vpc_id,
                NetworkSegmentType::Tenant,
                "10.70.0.0/25".parse::<IpNetwork>()?,
            ),
            (
                "bound-admin-parent",
                admin_vpc_id,
                NetworkSegmentType::Admin,
                "192.0.2.0/24".parse::<IpNetwork>()?,
            ),
        ] {
            db::network_segment::persist(
                NewNetworkSegment {
                    id: NetworkSegmentId::new(),
                    name: name.to_string(),
                    subdomain_id: None,
                    vpc_id: Some(vpc_id),
                    mtu: 1500,
                    prefixes: vec![NewNetworkPrefix {
                        prefix,
                        gateway: None,
                        dhcpv6_link_address: None,
                        num_reserved: 0,
                    }],
                    vlan_id: None,
                    vni: None,
                    segment_type,
                    can_stretch: None,
                    allocation_strategy: AllocationStrategy::Dynamic,
                    infer_slaac_eui64_addresses: false,
                },
                setup.as_mut(),
                NetworkSegmentControllerState::Ready,
            )
            .await?;
        }
        setup.commit().await?;

        validate_startup(&config(), &pool).await?;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn concurrent_candidates_reread_after_the_site_lock(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let vpc_id = VpcId::new();
        let site_prefix_id = SitePrefixId::new();
        let prefix: IpNetwork = "10.0.0.0/24".parse()?;
        let version = ConfigVersion::initial();
        let mut setup = pool.begin().await?;
        sqlx::query(
            "INSERT INTO tenants (organization_id, organization_name, version) \
             VALUES ('tenant-a', 'Tenant A', $1)",
        )
        .bind(version)
        .execute(setup.as_mut())
        .await?;
        sqlx::query(
            "INSERT INTO vpcs \
             (id, name, organization_id, version, network_virtualization_type, vni, \
              routing_profile_type, status) \
             VALUES ($1, 'routing-safety-vpc', 'tenant-a', $2, 'fnn', 1001, $3, \
                     '{\"vni\": 1001}'::jsonb)",
        )
        .bind(vpc_id)
        .bind(version)
        .bind(PROFILE)
        .execute(setup.as_mut())
        .await?;
        sqlx::query(
            "INSERT INTO site_prefixes \
             (id, prefix, authority, tenant_organization_id, routing_scope, \
              lifecycle_state, name, version) \
             VALUES ($1, $2, 'tenant_managed', 'tenant-a', 'datacenter_only', \
                     'ready', 'routing-safety-root', $3)",
        )
        .bind(site_prefix_id)
        .bind(prefix)
        .bind(version)
        .execute(setup.as_mut())
        .await?;
        setup.commit().await?;

        let config = config();
        let first_candidate = new_vpc_prefix(VpcPrefixId::new(), vpc_id, site_prefix_id, prefix);
        let mut first = pool.begin().await?;
        let first_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(first.as_mut())
            .await?;
        lock_site_mutation(first.as_mut()).await?;
        validate_vpc_prefix_candidate(&config, first.as_mut(), &first_candidate, &[]).await?;
        db::vpc_prefix::persist(first_candidate, version, first.as_mut()).await?;

        let second_pool = pool.clone();
        let second_config = config.clone();
        let second_candidate = new_vpc_prefix(VpcPrefixId::new(), vpc_id, site_prefix_id, prefix);
        let (pid_sender, pid_receiver) = tokio::sync::oneshot::channel();
        let second = tokio::spawn(async move {
            let mut txn = second_pool
                .begin()
                .await
                .map_err(|error| error.to_string())?;
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(txn.as_mut())
                .await
                .map_err(|error| error.to_string())?;
            pid_sender
                .send(pid)
                .map_err(|_| "could not report second transaction pid".to_string())?;
            lock_site_mutation(txn.as_mut())
                .await
                .map_err(|error| error.to_string())?;
            let result =
                validate_vpc_prefix_candidate(&second_config, txn.as_mut(), &second_candidate, &[])
                    .await;
            txn.rollback().await.map_err(|error| error.to_string())?;
            result.map_err(|error| error.to_string())
        });

        let second_pid = pid_receiver.await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let blocked_by_first: bool =
                    sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
                        .bind(first_pid)
                        .bind(second_pid)
                        .fetch_one(&pool)
                        .await?;
                if blocked_by_first {
                    return Ok::<(), sqlx::Error>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| std::io::Error::other("second candidate did not wait on the site lock"))??;

        first.commit().await?;
        let second_error = second
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
            .expect_err("the waiter must reject after re-reading the committed candidate");
        assert!(second_error.contains(OVERLAPPING_ADDRESS_SPACE));
        let persisted: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM network_vpc_prefixes WHERE prefix = $1")
                .bind(prefix)
                .fetch_one(&pool)
                .await?;
        assert_eq!(persisted, 1, "exactly one competing candidate may win");
        Ok(())
    }

    #[test]
    fn overlap_is_family_aware_and_detects_nesting() {
        let cases = [
            ("10.0.0.0/24", "10.0.0.0/24", true),
            ("10.0.0.0/24", "10.0.0.128/25", true),
            ("10.0.0.0/25", "10.0.0.128/25", false),
            ("2001:db8::/64", "2001:db8::/80", true),
            ("10.0.0.0/24", "2001:db8::/64", false),
        ];
        for (left, right, expected) in cases {
            assert_eq!(
                prefixes_overlap(left.parse().unwrap(), right.parse().unwrap()),
                expected,
                "{left} and {right}"
            );
        }
    }

    #[test]
    fn moderate_disjoint_inventory_reuses_empty_overlap_analysis() {
        let vpcs = [vpc("tenant-a", PROFILE, 1001)];
        let roots = [site_prefix("tenant-a", "10.0.0.0/16")];
        let addresses = (0..1024)
            .map(|index| {
                address(
                    index,
                    &vpcs[0],
                    &roots[0],
                    &format!("10.0.{}.{}/32", index / 256, index % 256),
                )
            })
            .collect();
        let state = state(&vpcs, &roots, addresses);
        let analysis = state.analyze_overlaps();

        assert!(analysis.all_indices.is_empty());
        assert!(analysis.tenant_reuse_indices.is_empty());
        assert!(analysis.occupancy_pairs.is_empty());
        assert_eq!(state.validate_tenant_reuse(&config(), &analysis), Ok(()));
    }

    #[test]
    fn only_equal_prefixes_are_overlap_eligible() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
        ];
        let cases = [
            ("10.0.0.0/24", "10.0.0.0/25", "10.0.0.0/24"),
            ("10.0.0.0/25", "10.0.0.0/24", "10.0.0.0/24"),
            ("2001:db8::/64", "2001:db8::/80", "2001:db8::/64"),
            ("2001:db8::/80", "2001:db8::/64", "2001:db8::/64"),
        ];

        for (left, right, root) in cases {
            let roots = [site_prefix("tenant-a", root), site_prefix("tenant-b", root)];
            let state = state(
                &vpcs,
                &roots,
                vec![
                    address(0, &vpcs[0], &roots[0], left),
                    address(1, &vpcs[1], &roots[1], right),
                ],
            );
            let analysis = state.analyze_overlaps();
            let failure =
                validate_candidate_addresses(&config(), &HashSet::new(), &state, &analysis)
                    .expect_err("nested overlap must not be eligible");
            assert_eq!(failure.violation, RoutingSafetyViolation::AddressConflict);
            assert!(
                matches!(
                    CarbideError::from(failure),
                    CarbideError::InvalidArgument(ref message) if message == OVERLAPPING_ADDRESS_SPACE
                ),
                "nested overlap {left} and {right} must retain the generic client error"
            );
        }
    }

    #[test]
    fn routing_profile_contract_separates_opt_in_from_isolation() {
        let safe = FnnRoutingProfileConfig {
            overlap_eligible: true,
            internal: Some(true),
            ..FnnRoutingProfileConfig::default()
        };
        assert!(profile_preserves_isolation(&safe));
        assert!(profile_allows_overlap(&safe));

        let route_target = RouteTargetConfig {
            asn: 64512,
            vni: 1001,
        };
        let prefix_filter = PrefixFilterPolicyEntry {
            prefix: "192.0.2.0/24".parse().expect("valid test prefix"),
        };
        let cases = [
            (
                "profile opt-in disabled",
                FnnRoutingProfileConfig {
                    overlap_eligible: false,
                    ..safe.clone()
                },
                true,
            ),
            (
                "external profile",
                FnnRoutingProfileConfig {
                    internal: Some(false),
                    ..safe.clone()
                },
                false,
            ),
            (
                "missing internal classification",
                FnnRoutingProfileConfig {
                    internal: None,
                    ..safe.clone()
                },
                false,
            ),
            (
                "route-target import",
                FnnRoutingProfileConfig {
                    route_target_imports: Some(vec![route_target.clone()]),
                    ..safe.clone()
                },
                false,
            ),
            (
                "route-target export",
                FnnRoutingProfileConfig {
                    route_targets_on_exports: Some(vec![route_target]),
                    ..safe.clone()
                },
                false,
            ),
            (
                "default-route leak",
                FnnRoutingProfileConfig {
                    leak_default_route_from_underlay: Some(true),
                    ..safe.clone()
                },
                false,
            ),
            (
                "tenant host-route leak",
                FnnRoutingProfileConfig {
                    leak_tenant_host_routes_to_underlay: Some(true),
                    ..safe.clone()
                },
                false,
            ),
            (
                "tenant leak community",
                FnnRoutingProfileConfig {
                    tenant_leak_communities_accepted: Some(true),
                    ..safe.clone()
                },
                false,
            ),
            (
                "accepted underlay leak",
                FnnRoutingProfileConfig {
                    accepted_leaks_from_underlay: Some(vec![prefix_filter.clone()]),
                    ..safe.clone()
                },
                false,
            ),
            (
                "allowed anycast prefix",
                FnnRoutingProfileConfig {
                    allowed_anycast_prefixes: Some(vec![prefix_filter]),
                    ..safe
                },
                false,
            ),
        ];
        for (name, profile, preserves_isolation) in cases {
            assert_eq!(
                profile_preserves_isolation(&profile),
                preserves_isolation,
                "{name} isolation"
            );
            assert!(!profile_allows_overlap(&profile), "{name} overlap");
        }
    }

    #[test]
    fn site_policy_rejects_every_feature_that_can_bridge_routing_domains() {
        struct SitePolicyCase {
            scenario: &'static str,
            mutate: fn(&mut CarbideConfig),
            expect: Option<(RoutingSafetyViolation, &'static str)>,
        }

        let cases = [
            SitePolicyCase {
                scenario: "safe defaults",
                mutate: |_| {},
                expect: None,
            },
            SitePolicyCase {
                scenario: "missing FNN configuration",
                mutate: |config| config.fnn = None,
                expect: Some((RoutingSafetyViolation::UnsafePolicy, "missing_fnn_config")),
            },
            SitePolicyCase {
                scenario: "open VPC isolation",
                mutate: |config| config.vpc_isolation_behavior = VpcIsolationBehaviorType::Open,
                expect: Some((
                    RoutingSafetyViolation::UnsafePolicy,
                    "site_isolation_not_mutual",
                )),
            },
            SitePolicyCase {
                scenario: "site-global VPC VNI",
                mutate: |config| config.site_global_vpc_vni = Some(1001),
                expect: Some((
                    RoutingSafetyViolation::UnsafePolicy,
                    "site_global_vpc_vni_enabled",
                )),
            },
            SitePolicyCase {
                scenario: "site anycast prefix",
                mutate: |config| {
                    config.anycast_site_prefixes = vec!["192.0.2.0/24".parse().unwrap()];
                },
                expect: Some((
                    RoutingSafetyViolation::UnsafePolicy,
                    "site_anycast_prefixes_enabled",
                )),
            },
            SitePolicyCase {
                scenario: "VMaaS configuration",
                mutate: |config| {
                    config.vmaas_config = Some(crate::cfg::file::VmaasConfig {
                        allow_instance_vf: true,
                        hbn_reps: None,
                        bridging: None,
                    });
                },
                expect: Some((RoutingSafetyViolation::UnsafePolicy, "vmaas_enabled")),
            },
            SitePolicyCase {
                scenario: "common internal route target",
                mutate: |config| {
                    config.fnn.as_mut().unwrap().common_internal_route_target =
                        Some(RouteTargetConfig { asn: 64512, vni: 1 });
                },
                expect: Some((
                    RoutingSafetyViolation::UnsafePolicy,
                    "common_internal_route_target_enabled",
                )),
            },
            SitePolicyCase {
                scenario: "additional route-target import",
                mutate: |config| {
                    config.fnn.as_mut().unwrap().additional_route_target_imports =
                        vec![RouteTargetConfig { asn: 64512, vni: 1 }];
                },
                expect: Some((
                    RoutingSafetyViolation::UnsafePolicy,
                    "additional_route_target_imports_enabled",
                )),
            },
            SitePolicyCase {
                scenario: "deny-only site NSG override",
                mutate: |config| {
                    config.network_security_group.policy_overrides =
                        vec![security_group_rule(NetworkSecurityGroupRuleAction::Deny)];
                },
                expect: None,
            },
            SitePolicyCase {
                scenario: "site NSG permit override",
                mutate: |config| {
                    config.network_security_group.policy_overrides =
                        vec![security_group_rule(NetworkSecurityGroupRuleAction::Permit)];
                },
                expect: Some((
                    RoutingSafetyViolation::UnsafePolicy,
                    "site_nsg_permit_override_enabled",
                )),
            },
        ];
        let vpcs = [];
        let roots = [];
        let state = state(&vpcs, &roots, vec![]);

        for SitePolicyCase {
            scenario,
            mutate,
            expect,
        } in cases
        {
            let mut config = config();
            mutate(&mut config);
            let got = state
                .validate_site_policy(&config)
                .map_err(|failure| (failure.violation, failure.reason))
                .err();
            assert_eq!(got, expect, "{scenario}");
        }
    }

    #[test]
    fn security_group_safety_requires_stateless_deny_only_rules() {
        use carbide_test_support::{Check, check_values};

        check_values(
            [
                Check {
                    scenario: "stateless empty group",
                    input: (false, vec![]),
                    expect: true,
                },
                Check {
                    scenario: "stateless deny-only group",
                    input: (false, vec![NetworkSecurityGroupRuleAction::Deny]),
                    expect: true,
                },
                Check {
                    scenario: "stateless group containing a permit",
                    input: (
                        false,
                        vec![
                            NetworkSecurityGroupRuleAction::Deny,
                            NetworkSecurityGroupRuleAction::Permit,
                        ],
                    ),
                    expect: false,
                },
                Check {
                    scenario: "stateful empty group",
                    input: (true, vec![]),
                    expect: false,
                },
                Check {
                    scenario: "stateful deny-only group",
                    input: (true, vec![NetworkSecurityGroupRuleAction::Deny]),
                    expect: false,
                },
                Check {
                    scenario: "stateful group containing a permit",
                    input: (true, vec![NetworkSecurityGroupRuleAction::Permit]),
                    expect: false,
                },
            ],
            |(stateful_egress, actions)| {
                network_security_group_is_safe(&network_security_group(
                    NetworkSecurityGroupId::from_str("safety-table").unwrap(),
                    "tenant-a",
                    stateful_egress,
                    actions.into_iter().map(security_group_rule).collect(),
                ))
            },
        );
    }

    #[test]
    fn isolated_eligible_overlap_is_accepted_but_site_gate_freezes_expansion() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
        ];
        let state = overlapping_state(&vpcs, &roots);
        let mut config = config();

        assert_eq!(state.validate(&config), Ok(()));
        config.tenant_prefix_overlap_enabled = false;
        let analysis = state.analyze_overlaps();
        assert!(matches!(
            validate_candidate_addresses(&config, &HashSet::new(), &state, &analysis),
            Err(failure) if failure.violation == RoutingSafetyViolation::OverlapDisabled
        ));
        // Startup ignores the admission gate: an operator can turn future
        // expansion off without taking a safe existing deployment down.
        assert_eq!(state.validate(&config), Ok(()));
    }

    #[test]
    fn overlap_requires_tenant_site_prefix_and_distinct_native_vnis() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
        ];
        let mut roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
        ];
        roots[1].status.authority = SitePrefixAuthority::OperatorManaged;
        assert_eq!(
            violation(overlapping_state(&vpcs, &roots).validate(&config())),
            Err(RoutingSafetyViolation::IneligibleOverlap)
        );

        roots[1].status.authority = SitePrefixAuthority::TenantManaged;
        let mut colliding_vpcs = vpcs;
        colliding_vpcs[1].status.vni = Some(1001);
        assert_eq!(
            violation(overlapping_state(&colliding_vpcs, &roots).validate(&config())),
            Err(RoutingSafetyViolation::UnsafePolicy)
        );
    }

    #[test]
    fn candidate_rejects_direct_and_same_vpc_overlap() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
        ];
        let mut direct = overlapping_state(&vpcs, &roots);
        direct.addresses[1].source = AddressSource::Network { id: None };
        assert_eq!(direct.validate(&config()), Ok(()));
        let analysis = direct.analyze_overlaps();
        for (gate_enabled, expected_violation) in [
            (false, RoutingSafetyViolation::OverlapDisabled),
            (true, RoutingSafetyViolation::AddressConflict),
        ] {
            let mut candidate_config = config();
            candidate_config.tenant_prefix_overlap_enabled = gate_enabled;
            let failure = validate_candidate_addresses(
                &candidate_config,
                &HashSet::new(),
                &direct,
                &analysis,
            )
            .expect_err("direct-prefix candidate overlap must be rejected");
            assert_eq!(failure.violation, expected_violation);
            assert!(matches!(
                CarbideError::from(failure),
                CarbideError::InvalidArgument(ref message) if message == OVERLAPPING_ADDRESS_SPACE
            ));
        }

        let mut same_vpc = overlapping_state(&vpcs, &roots);
        same_vpc.addresses[1].vpc_id = vpcs[0].id;
        assert_eq!(same_vpc.validate(&config()), Ok(()));
        let analysis = same_vpc.analyze_overlaps();
        let failure =
            validate_candidate_addresses(&config(), &HashSet::new(), &same_vpc, &analysis)
                .expect_err("same-VPC candidate overlap must be rejected");
        assert_eq!(failure.violation, RoutingSafetyViolation::AddressConflict);
        assert!(matches!(
            CarbideError::from(failure),
            CarbideError::InvalidArgument(ref message) if message == OVERLAPPING_ADDRESS_SPACE
        ));

        let same_tenant_vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-a", PROFILE, 1002),
        ];
        let same_tenant_roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-a", "10.0.0.0/24"),
        ];
        assert_eq!(
            violation(overlapping_state(&same_tenant_vpcs, &same_tenant_roots).validate(&config()),),
            Err(RoutingSafetyViolation::IneligibleOverlap)
        );

        let same_root_addresses = vec![
            address(0, &vpcs[0], &roots[0], "10.0.0.0/24"),
            address(1, &vpcs[1], &roots[0], "10.0.0.0/24"),
        ];
        assert_eq!(
            violation(state(&vpcs, &roots, same_root_addresses).validate(&config())),
            Err(RoutingSafetyViolation::IneligibleOverlap)
        );
    }

    #[test]
    fn retained_instance_union_resolves_existing_unbound_segments() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
            vpc("tenant-c", PROFILE, 1003),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
        ];
        let segment_id = NetworkSegmentId::new();
        let mut current = InstanceNetworkConfig::for_segment_ids(&[segment_id], &[], &[vpcs[0].id]);
        current.auto_config = Some(InstanceNetworkAutoConfig { vpc_id: vpcs[0].id });
        let old_config = InstanceNetworkConfig {
            auto_config: Some(InstanceNetworkAutoConfig { vpc_id: vpcs[0].id }),
            ..Default::default()
        };
        let new_config = InstanceNetworkConfig {
            auto_config: Some(InstanceNetworkAutoConfig { vpc_id: vpcs[2].id }),
            ..Default::default()
        };
        let mut addresses = db::routing_safety::RoutingAddressSnapshot {
            vpcs: vpcs.to_vec(),
            site_prefixes: roots.to_vec(),
            vpc_prefixes: vec![
                vpc_prefix(&vpcs[0], &roots[0], "10.0.0.0/24"),
                vpc_prefix(&vpcs[1], &roots[1], "10.0.0.0/24"),
            ],
            network_segments: vec![unbound_host_inband_segment(segment_id)],
        };
        let policy = db::routing_safety::RoutingPolicySnapshot {
            peerings: Vec::new(),
            network_security_groups: Vec::new(),
            instances: vec![db::routing_safety::RoutingInstance {
                id: InstanceId::new(),
                network_config: sqlx::types::Json(current),
                update_network_config_request: Some(sqlx::types::Json(
                    InstanceNetworkConfigUpdate {
                        old_config,
                        new_config,
                    },
                )),
                network_security_group_id: None,
            }],
        };

        {
            let mut state = RoutingState::from_addresses(&addresses);
            state.apply_policy_paths(&policy, &addresses);
            assert_eq!(state.instance_paths.len(), 1);
            assert_eq!(
                state.instance_paths[0].vpc_ids,
                [vpcs[0].id, vpcs[2].id].into_iter().collect()
            );
            assert!(!state.instance_paths[0].has_unresolved_reference);
            assert_eq!(state.validate(&config()), Ok(()));
        }

        addresses.vpcs[2].config.routing_profile_type = Some(UNSAFE_PROFILE.to_string());
        {
            let mut state = RoutingState::from_addresses(&addresses);
            state.apply_policy_paths(&policy, &addresses);
            assert_eq!(
                violation(state.validate(&config())),
                Err(RoutingSafetyViolation::UnsafePolicy),
                "the pending new-side VPC must remain graph-active"
            );
        }

        addresses.vpcs[2].config.routing_profile_type = Some(PROFILE.to_string());
        addresses.network_segments.clear();
        let mut missing = RoutingState::from_addresses(&addresses);
        missing.apply_policy_paths(&policy, &addresses);
        assert!(missing.instance_paths[0].has_unresolved_reference);
        assert_eq!(
            violation(missing.validate(&config())),
            Err(RoutingSafetyViolation::UnsafePolicy),
            "a missing retained segment must fail closed"
        );
    }

    #[test]
    fn peering_overlap_is_rejected_in_both_endpoint_orders() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
        ];
        let mut config = config();
        config.vpc_peering_policy_on_existing = Some(VpcPeeringPolicy::Mixed);

        for peering in [(vpcs[0].id, vpcs[1].id), (vpcs[1].id, vpcs[0].id)] {
            let mut state = overlapping_state(&vpcs, &roots);
            state.peerings.push(peering);
            assert_eq!(
                violation(state.validate(&config)),
                Err(RoutingSafetyViolation::ReachableOverlap)
            );
        }

        config.vpc_peering_policy_on_existing = None;
        config.vpc_peering_policy = Some(VpcPeeringPolicy::Exclusive);
        let mut state = overlapping_state(&vpcs, &roots);
        state.peerings.push((vpcs[0].id, vpcs[1].id));
        assert_eq!(
            violation(state.validate(&config)),
            Err(RoutingSafetyViolation::ReachableOverlap),
            "existing-peer policy must fall back to the rendered peering policy"
        );

        config.vpc_peering_policy_on_existing = Some(VpcPeeringPolicy::None);
        assert_eq!(
            violation(state.validate(&config)),
            Err(RoutingSafetyViolation::ReachableOverlap),
            "FNN peer-VNI imports remain active for an existing peering even when prefix imports are disabled"
        );

        config.vpc_peering_policy_on_existing = None;
        config.vpc_peering_policy = None;
        assert_eq!(
            state.validate(&config),
            Ok(()),
            "the renderer imports neither peer prefixes nor peer VNIs when both policy options are unset"
        );
    }

    #[test]
    fn peering_activity_matches_renderer_directionality() {
        let virtualization_types = [
            VpcVirtualizationType::EthernetVirtualizer,
            VpcVirtualizationType::EthernetVirtualizerWithNvue,
            VpcVirtualizationType::Fnn,
            VpcVirtualizationType::Flat,
        ];
        assert_eq!(
            ALL_VPC_VIRTUALIZATION_TYPES,
            virtualization_types.as_slice(),
            "the directionality matrix must enumerate every virtualization type"
        );
        let cases = [
            (
                VpcPeeringPolicy::Exclusive,
                [
                    [true, true, false, true],
                    [true, true, false, true],
                    [false, false, true, true],
                    [true, true, true, true],
                ],
            ),
            (VpcPeeringPolicy::Mixed, [[true; 4]; 4]),
            (
                VpcPeeringPolicy::None,
                [
                    [false, false, false, false],
                    [false, false, false, false],
                    [false, false, true, true],
                    [false, false, false, false],
                ],
            ),
        ];

        for (policy, expected) in cases {
            for (receiver_index, receiver_type) in virtualization_types.iter().copied().enumerate()
            {
                for (peer_index, peer_type) in virtualization_types.iter().copied().enumerate() {
                    assert_eq!(
                        peering_direction_is_active(policy, receiver_type, peer_type),
                        expected[receiver_index][peer_index],
                        "{policy:?}: {receiver_type:?} receiver, {peer_type:?} peer"
                    );
                }
            }
        }
    }

    #[test]
    fn configured_peering_with_missing_endpoint_fails_closed() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
        ];
        let mut state = overlapping_state(&vpcs, &roots);
        state.peerings.push((vpcs[0].id, VpcId::new()));

        let mut config = config();
        config.vpc_peering_policy_on_existing = Some(VpcPeeringPolicy::Mixed);
        let failure = state
            .validate(&config)
            .expect_err("missing peer must fail closed");
        assert_eq!(failure.violation, RoutingSafetyViolation::UnsafePolicy);
        assert_eq!(failure.reason, "missing_peered_vpc");
    }

    #[test]
    fn dormant_peering_does_not_activate_latent_unsafe_profile() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
            vpc("tenant-c", UNSAFE_PROFILE, 1003),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
        ];
        let mut state = overlapping_state(&vpcs, &roots);
        state.peerings.push((vpcs[0].id, vpcs[2].id));

        let mut config = config();
        config.vpc_peering_policy = None;
        config.vpc_peering_policy_on_existing = None;
        assert_eq!(
            state.validate(&config),
            Ok(()),
            "an unrendered peering must not make its otherwise unused endpoint active"
        );

        config.vpc_peering_policy_on_existing = Some(VpcPeeringPolicy::None);
        assert_eq!(
            violation(state.validate(&config)),
            Err(RoutingSafetyViolation::UnsafePolicy),
            "a configured policy keeps capability-driven FNN peer-VNI imports active"
        );
    }

    #[test]
    fn receiver_rejects_overlapping_sibling_peers() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
            vpc("tenant-c", PROFILE, 1003),
        ];
        let roots = [
            site_prefix("tenant-a", "192.0.2.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
            site_prefix("tenant-c", "10.0.0.0/24"),
        ];
        let mut state = state(
            &vpcs,
            &roots,
            vec![
                address(0, &vpcs[1], &roots[1], "10.0.0.0/24"),
                address(1, &vpcs[2], &roots[2], "10.0.0.0/24"),
            ],
        );
        state.peerings = vec![(vpcs[0].id, vpcs[1].id), (vpcs[0].id, vpcs[2].id)];
        let mut config = config();
        config.vpc_peering_policy_on_existing = Some(VpcPeeringPolicy::Mixed);

        assert_eq!(
            violation(state.validate(&config)),
            Err(RoutingSafetyViolation::ReachableOverlap)
        );
    }

    #[test]
    fn instance_receiver_rejects_direct_and_peer_visible_overlap() {
        #[derive(Clone, Copy)]
        struct Case {
            name: &'static str,
            attached_vpc_indices: &'static [usize],
            peering_indices: Option<(usize, usize)>,
        }

        let cases = [
            Case {
                name: "direct multi-home",
                attached_vpc_indices: &[0, 1],
                peering_indices: None,
            },
            Case {
                name: "multi-home through peer",
                attached_vpc_indices: &[0, 2],
                peering_indices: Some((2, 1)),
            },
            Case {
                name: "multi-home through reversed peer",
                attached_vpc_indices: &[0, 2],
                peering_indices: Some((1, 2)),
            },
        ];

        for case in cases {
            let vpcs = [
                vpc("tenant-a", PROFILE, 1001),
                vpc("tenant-b", PROFILE, 1002),
                vpc("tenant-a", PROFILE, 1003),
            ];
            let roots = [
                site_prefix("tenant-a", "10.0.0.0/24"),
                site_prefix("tenant-b", "10.0.0.0/24"),
            ];
            let mut state = overlapping_state(&vpcs, &roots);
            let path = instance_path(
                case.attached_vpc_indices
                    .iter()
                    .map(|index| vpcs[*index].id),
            );
            let instance_id = path.instance_id;
            state.instance_paths.push(path);
            if let Some((left, right)) = case.peering_indices {
                state.peerings.push((vpcs[left].id, vpcs[right].id));
            }

            let mut config = config();
            config.vpc_peering_policy = None;
            config.vpc_peering_policy_on_existing =
                case.peering_indices.map(|_| VpcPeeringPolicy::Mixed);
            let failure = state
                .validate(&config)
                .expect_err("instance receiver must not see both reused prefixes");
            assert_eq!(
                failure.violation,
                RoutingSafetyViolation::ReachableOverlap,
                "{}",
                case.name
            );
            assert!(
                failure
                    .resource_ids
                    .contains(&format!("instance:{instance_id}")),
                "{}: instance context",
                case.name
            );
        }
    }

    #[test]
    fn peering_and_prefix_order_reject_the_same_reachable_overlap() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
        ];
        let mut config = config();
        config.vpc_peering_policy_on_existing = Some(VpcPeeringPolicy::Mixed);

        let mut prefix_first = overlapping_state(&vpcs, &roots);
        assert_eq!(prefix_first.validate(&config), Ok(()));
        prefix_first.peerings.push((vpcs[0].id, vpcs[1].id));
        assert_eq!(
            violation(prefix_first.validate(&config)),
            Err(RoutingSafetyViolation::ReachableOverlap),
            "adding the peering after the duplicate prefix must fail"
        );

        let mut peer_first = state(
            &vpcs,
            &roots,
            vec![address(0, &vpcs[0], &roots[0], "10.0.0.0/24")],
        );
        peer_first.peerings.push((vpcs[0].id, vpcs[1].id));
        assert_eq!(peer_first.validate(&config), Ok(()));
        let current_pairs = peer_first.analyze_overlaps().occupancy_pairs;
        peer_first
            .addresses
            .push(address(1, &vpcs[1], &roots[1], "10.0.0.0/24"));
        let proposed_analysis = peer_first.analyze_overlaps();
        assert_eq!(
            validate_candidate_addresses(&config, &current_pairs, &peer_first, &proposed_analysis,),
            Ok(())
        );
        assert!(matches!(
            peer_first.validate_policy_paths(&config, &proposed_analysis),
            Err(failure) if failure.violation == RoutingSafetyViolation::ReachableOverlap
        ));
    }

    #[test]
    fn latent_unsafe_profile_does_not_block_until_its_vpc_becomes_active() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
            vpc("tenant-c", UNSAFE_PROFILE, 1003),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
            site_prefix("tenant-c", "192.0.2.0/24"),
        ];
        let mut state = overlapping_state(&vpcs, &roots);
        assert_eq!(state.validate(&config()), Ok(()));

        state
            .addresses
            .push(address(2, &vpcs[2], &roots[2], "192.0.2.0/24"));
        assert_eq!(
            violation(state.validate(&config())),
            Err(RoutingSafetyViolation::UnsafePolicy)
        );
    }

    #[test]
    fn routing_profile_contract_allows_unrelated_active_vpc_without_opt_in() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
            vpc("tenant-c", ISOLATED_PROFILE, 1003),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
            site_prefix("tenant-c", "192.0.2.0/24"),
        ];
        let mut state = overlapping_state(&vpcs, &roots);
        state
            .addresses
            .push(address(2, &vpcs[2], &roots[2], "192.0.2.0/24"));

        assert_eq!(state.validate(&config()), Ok(()));
    }

    #[test]
    fn routing_profile_contract_requires_opt_in_for_overlap_participants() {
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", ISOLATED_PROFILE, 1002),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
        ];

        let failure = overlapping_state(&vpcs, &roots)
            .validate(&config())
            .expect_err("each overlapping participant must opt in");
        assert_eq!(failure.violation, RoutingSafetyViolation::UnsafePolicy);
        assert_eq!(failure.reason, "unsafe_vpc_routing_profile");
    }

    #[test]
    fn routing_profile_contract_requires_resolvable_profile_when_active() {
        let mut profileless = vpc("tenant-c", PROFILE, 1003);
        profileless.config.routing_profile_type = None;
        let vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
            profileless,
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
            site_prefix("tenant-c", "192.0.2.0/24"),
        ];
        let mut state = overlapping_state(&vpcs, &roots);
        assert_eq!(state.validate(&config()), Ok(()));

        state
            .addresses
            .push(address(2, &vpcs[2], &roots[2], "192.0.2.0/24"));
        let failure = state
            .validate(&config())
            .expect_err("a graph-active FNN VPC must have a resolvable profile");
        assert_eq!(failure.violation, RoutingSafetyViolation::UnsafePolicy);
        assert_eq!(failure.reason, "unresolved_vpc_routing_profile");
    }

    #[test]
    fn active_fnn_vnis_must_be_present_and_unique() {
        let cases = [
            ("unique VNI", Some(1003), None),
            ("missing VNI", None, Some("missing_active_vpc_vni")),
            (
                "duplicate VNI",
                Some(1001),
                Some("duplicate_active_vpc_vni"),
            ),
        ];

        for (scenario, third_vni, expected_reason) in cases {
            let mut third = vpc("tenant-c", PROFILE, 1003);
            third.status.vni = third_vni;
            let vpcs = [
                vpc("tenant-a", PROFILE, 1001),
                vpc("tenant-b", PROFILE, 1002),
                third,
            ];
            let roots = [
                site_prefix("tenant-a", "10.0.0.0/24"),
                site_prefix("tenant-b", "10.0.0.0/24"),
                site_prefix("tenant-c", "192.0.2.0/24"),
            ];
            let mut state = overlapping_state(&vpcs, &roots);
            state
                .addresses
                .push(address(2, &vpcs[2], &roots[2], "192.0.2.0/24"));

            assert_eq!(
                state
                    .validate(&config())
                    .map_err(|failure| failure.reason)
                    .err(),
                expected_reason,
                "{scenario}"
            );
        }
    }

    #[test]
    fn control_path_exemption_requires_authoritative_unconsumed_admin_vpc() {
        #[derive(Clone, Copy)]
        enum Consumer {
            None,
            Instance,
            Peering,
        }

        const CONTROL_ONLY: &[NetworkSegmentType] = &[NetworkSegmentType::Admin];
        const HYBRID: &[NetworkSegmentType] =
            &[NetworkSegmentType::Admin, NetworkSegmentType::Tenant];
        #[derive(Clone, Copy)]
        struct Case {
            name: &'static str,
            tenant: &'static str,
            segment_types: &'static [NetworkSegmentType],
            profile: &'static str,
            admin_enabled: bool,
            configured_admin_vni: u32,
            persisted_config_vni: i32,
            persisted_status_vni: i32,
            consumer: Consumer,
            expect_exempt: bool,
            expect_reason: Option<&'static str>,
        }
        let authoritative = Case {
            name: "authoritative unconsumed admin VPC",
            tenant: "carbide_internal",
            segment_types: CONTROL_ONLY,
            profile: UNSAFE_PROFILE,
            admin_enabled: true,
            configured_admin_vni: 1003,
            persisted_config_vni: 1003,
            persisted_status_vni: 1003,
            consumer: Consumer::None,
            expect_exempt: true,
            expect_reason: None,
        };
        let cases = [
            authoritative,
            Case {
                name: "tenant-owned Admin-only VPC",
                tenant: "tenant-c",
                expect_exempt: false,
                expect_reason: Some("unsafe_vpc_routing_profile"),
                ..authoritative
            },
            Case {
                name: "hybrid VPC with unsafe profile",
                segment_types: HYBRID,
                expect_exempt: false,
                expect_reason: Some("unsafe_vpc_routing_profile"),
                ..authoritative
            },
            Case {
                name: "hybrid VPC with permit NSG",
                segment_types: HYBRID,
                profile: PROFILE,
                expect_exempt: false,
                expect_reason: Some("unsafe_active_network_security_group"),
                ..authoritative
            },
            Case {
                name: "instance-consumed authoritative admin VPC",
                consumer: Consumer::Instance,
                expect_exempt: false,
                expect_reason: Some("unsafe_vpc_routing_profile"),
                ..authoritative
            },
            Case {
                name: "peering-consumed authoritative admin VPC",
                consumer: Consumer::Peering,
                expect_exempt: false,
                expect_reason: Some("unsafe_vpc_routing_profile"),
                ..authoritative
            },
            Case {
                name: "disabled admin config",
                admin_enabled: false,
                expect_exempt: false,
                expect_reason: Some("unsafe_vpc_routing_profile"),
                ..authoritative
            },
            Case {
                name: "configured VNI mismatch",
                configured_admin_vni: 2003,
                expect_exempt: false,
                expect_reason: Some("unsafe_vpc_routing_profile"),
                ..authoritative
            },
            Case {
                name: "persisted config VNI mismatch",
                persisted_config_vni: 2003,
                expect_exempt: false,
                expect_reason: Some("unsafe_vpc_routing_profile"),
                ..authoritative
            },
            Case {
                name: "persisted status VNI mismatch",
                persisted_status_vni: 2003,
                expect_exempt: false,
                expect_reason: Some("unsafe_vpc_routing_profile"),
                ..authoritative
            },
        ];

        for case in cases {
            let group_id = NetworkSecurityGroupId::from_str("hybrid-vpc-policy").unwrap();
            let mut vpcs = [
                vpc("tenant-a", PROFILE, 1001),
                vpc("tenant-b", PROFILE, 1002),
                vpc(case.tenant, case.profile, case.persisted_status_vni),
            ];
            vpcs[2].config.vni = Some(case.persisted_config_vni);
            vpcs[2].config.network_security_group_id = Some(group_id.clone());
            let roots = [
                site_prefix("tenant-a", "10.0.0.0/24"),
                site_prefix("tenant-b", "10.0.0.0/24"),
                site_prefix(case.tenant, "192.0.2.0/24"),
            ];
            let addresses = db::routing_safety::RoutingAddressSnapshot {
                vpcs: vpcs.to_vec(),
                site_prefixes: roots.to_vec(),
                vpc_prefixes: vec![
                    vpc_prefix(&vpcs[0], &roots[0], "10.0.0.0/24"),
                    vpc_prefix(&vpcs[1], &roots[1], "10.0.0.0/24"),
                    vpc_prefix(&vpcs[2], &roots[2], "192.0.2.0/24"),
                ],
                network_segments: case
                    .segment_types
                    .iter()
                    .copied()
                    .map(|segment_type| bound_segment(vpcs[2].id, segment_type))
                    .collect(),
            };
            let mut state = RoutingState::from_addresses(&addresses);
            state.network_security_groups.insert(
                group_id.clone(),
                network_security_group(
                    group_id,
                    case.tenant,
                    false,
                    vec![security_group_rule(NetworkSecurityGroupRuleAction::Permit)],
                ),
            );
            match case.consumer {
                Consumer::None => {}
                Consumer::Instance => state.instance_paths.push(instance_path([vpcs[2].id])),
                Consumer::Peering => state.peerings.push((vpcs[2].id, vpcs[0].id)),
            }
            let mut config = config();
            config.fnn.as_mut().unwrap().admin_vpc = Some(crate::cfg::file::AdminFnnConfig {
                enabled: case.admin_enabled,
                vpc_vni: Some(case.configured_admin_vni),
                routing_profile: FnnRoutingProfileConfig::default(),
            });

            assert_eq!(
                state.is_unconsumed_admin_vpc(&config, &vpcs[2]),
                case.expect_exempt,
                "{}: control classification",
                case.name
            );
            assert_eq!(
                state
                    .validate(&config)
                    .map_err(|failure| failure.reason)
                    .err(),
                case.expect_reason,
                "{}: active-path validation",
                case.name
            );
        }
    }

    #[test]
    fn active_interface_overrides_and_stateful_security_groups_are_unsafe() {
        let mut vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
        ];
        let roots = [
            site_prefix("tenant-a", "10.0.0.0/24"),
            site_prefix("tenant-b", "10.0.0.0/24"),
        ];
        let group_id = NetworkSecurityGroupId::from_str("unsafe-group").unwrap();
        vpcs[0].config.network_security_group_id = Some(group_id.clone());
        vpcs[0]
            .metadata
            .labels
            .insert("kind".to_string(), "admin".to_string());
        let mut state = overlapping_state(&vpcs, &roots);
        let group = network_security_group(group_id.clone(), "tenant-a", true, vec![]);
        state.network_security_groups.insert(group_id, group);
        assert_eq!(
            violation(state.validate(&config())),
            Err(RoutingSafetyViolation::UnsafePolicy)
        );

        let mut vpcs = [
            vpc("tenant-a", PROFILE, 1001),
            vpc("tenant-b", PROFILE, 1002),
        ];
        vpcs[0].config.network_security_group_id = None;
        let mut state = overlapping_state(&vpcs, &roots);
        state.instance_paths.push(InstancePath {
            instance_id: InstanceId::new(),
            vpc_ids: HashSet::from([vpcs[0].id]),
            network_security_group_id: None,
            has_routing_override: true,
            has_unresolved_reference: false,
        });
        assert_eq!(
            violation(state.validate(&config())),
            Err(RoutingSafetyViolation::UnsafePolicy)
        );

        let mut state = overlapping_state(&vpcs, &roots);
        state.instance_paths.push(InstancePath {
            instance_id: InstanceId::new(),
            vpc_ids: HashSet::new(),
            network_security_group_id: None,
            has_routing_override: true,
            has_unresolved_reference: true,
        });
        assert_eq!(
            violation(state.validate(&config())),
            Err(RoutingSafetyViolation::UnsafePolicy)
        );
    }

    #[test]
    fn public_overlap_errors_do_not_disclose_foreign_resources() {
        let disabled_error = CarbideError::from(RoutingSafetyViolation::OverlapDisabled);
        assert!(matches!(
            disabled_error,
            CarbideError::InvalidArgument(ref message) if message == OVERLAPPING_ADDRESS_SPACE
        ));

        for violation in [
            RoutingSafetyViolation::OverlapDisabled,
            RoutingSafetyViolation::AddressConflict,
            RoutingSafetyViolation::IneligibleOverlap,
            RoutingSafetyViolation::ReachableOverlap,
            RoutingSafetyViolation::UnsafePolicy,
        ] {
            let error = CarbideError::from(violation).to_string();
            assert!(!error.contains("10.0.0.0"));
            assert!(!error.contains("tenant-a"));
            assert!(!error.contains("00000000-0000"));
        }
    }
}
