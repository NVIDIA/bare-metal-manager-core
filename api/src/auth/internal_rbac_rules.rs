/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use super::ExternalUserInfo;
use crate::auth::Principal;
use std::collections::HashMap;
use std::sync::LazyLock;

static INTERNAL_RBAC_RULES: LazyLock<InternalRBACRules> = LazyLock::new(InternalRBACRules::new);

#[derive(Debug)]
pub struct InternalRBACRules {
    perms: std::collections::HashMap<String, RuleInfo>,
}

#[derive(Debug)]
enum RulePrincipal {
    ForgeAdminCLI,
    Machineatron,
    SiteAgent,
    Agent, // Agent on the DPU, NOT site agent
    Scout,
    Dns,
    Dhcp,
    Ssh,
    Health,
    Pxe,
    Anonymous, // Permitted for everything
}
use self::RulePrincipal::{
    Agent, Anonymous, Dhcp, Dns, ForgeAdminCLI, Health, Machineatron, Pxe, Scout, SiteAgent, Ssh,
};

impl InternalRBACRules {
    pub fn new() -> Self {
        let mut x = Self {
            perms: HashMap::default(),
        };

        // Add additional permissions to the list below.
        x.perm("Version", vec![Anonymous]);
        x.perm("CreateDomain", vec![]);
        x.perm("UpdateDomain", vec![]);
        x.perm("DeleteDomain", vec![]);
        x.perm("FindDomain", vec![ForgeAdminCLI]);
        x.perm("CreateVpc", vec![SiteAgent, Machineatron]);
        x.perm("UpdateVpc", vec![SiteAgent]);
        x.perm("UpdateVpcVirtualization", vec![ForgeAdminCLI]);
        x.perm("DeleteVpc", vec![Machineatron, SiteAgent]);
        x.perm("FindVpcIds", vec![SiteAgent, ForgeAdminCLI, Machineatron]);
        x.perm("FindVpcsByIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindVpcs", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateVpcPrefix", vec![SiteAgent]);
        x.perm("SearchVpcPrefixes", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("GetVpcPrefixes", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateVpcPrefix", vec![SiteAgent]);
        x.perm("DeleteVpcPrefix", vec![SiteAgent]);
        x.perm(
            "FindNetworkSegmentIds",
            vec![ForgeAdminCLI, Machineatron, SiteAgent],
        );
        x.perm(
            "FindNetworkSegmentsByIds",
            vec![ForgeAdminCLI, Machineatron, SiteAgent],
        );
        x.perm(
            "FindNetworkSegments",
            vec![ForgeAdminCLI, Machineatron, SiteAgent],
        );
        x.perm("CreateNetworkSegment", vec![Machineatron, SiteAgent]);
        x.perm("DeleteNetworkSegment", vec![Machineatron, SiteAgent]);
        x.perm("NetworkSegmentsForVpc", vec![]);
        x.perm("FindIBPartitionIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindIBPartitionsByIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindIBPartitions", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateIBPartition", vec![SiteAgent]);
        x.perm("DeleteIBPartition", vec![SiteAgent]);
        x.perm("IBPartitionsForTenant", vec![]);
        x.perm(
            "AllocateInstance",
            vec![ForgeAdminCLI, Machineatron, SiteAgent],
        );
        x.perm("ReleaseInstance", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateInstanceOperatingSystem", vec![SiteAgent]);
        x.perm("UpdateInstanceConfig", vec![SiteAgent]);
        x.perm("FindInstanceIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindInstancesByIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindInstances", vec![ForgeAdminCLI, SiteAgent, Ssh]);
        x.perm(
            "FindInstanceByMachineID",
            vec![ForgeAdminCLI, Agent, SiteAgent],
        );
        x.perm("RecordObservedInstanceNetworkStatus", vec![]);
        x.perm(
            "GetManagedHostNetworkConfig",
            vec![ForgeAdminCLI, Agent, Machineatron],
        );
        x.perm("RecordDpuNetworkStatus", vec![Agent, Machineatron]);
        x.perm("RecordHardwareHealthReport", vec![Health, Ssh]);
        x.perm("GetHardwareHealthReport", vec![]);
        x.perm("ListHealthReportOverrides", vec![ForgeAdminCLI]);
        x.perm("InsertHealthReportOverride", vec![ForgeAdminCLI]);
        x.perm("RemoveHealthReportOverride", vec![ForgeAdminCLI]);
        x.perm("DpuAgentUpgradeCheck", vec![Scout]);
        x.perm("DpuAgentUpgradePolicyAction", vec![ForgeAdminCLI]);
        x.perm("LookupRecord", vec![Dns]);
        x.perm("InvokeInstancePower", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("ForgeAgentControl", vec![Machineatron, Scout]);
        x.perm("DiscoverMachine", vec![Anonymous]);
        x.perm("RenewMachineCertificate", vec![Agent]);
        x.perm("DiscoveryCompleted", vec![Machineatron, Scout]);
        x.perm("CleanupMachineCompleted", vec![Machineatron, Scout]);
        x.perm("ReportForgeScoutError", vec![Scout]);
        x.perm("DiscoverDhcp", vec![Dhcp, Machineatron]);
        x.perm("GetMachine", vec![ForgeAdminCLI, Agent, Machineatron]);
        x.perm(
            "FindMachines",
            vec![ForgeAdminCLI, Machineatron, SiteAgent, Ssh],
        );
        x.perm("FindInterfaces", vec![ForgeAdminCLI]);
        x.perm("DeleteInterface", vec![ForgeAdminCLI]);
        x.perm("FindIpAddress", vec![ForgeAdminCLI]);
        x.perm(
            "FindMachineIds",
            vec![ForgeAdminCLI, Machineatron, Health, SiteAgent, Ssh],
        );
        x.perm(
            "FindMachinesByIds",
            vec![ForgeAdminCLI, Machineatron, Health, SiteAgent, Ssh],
        );
        x.perm("FindConnectedDevicesByDpuMachineIds", vec![ForgeAdminCLI]);
        x.perm("FindMachineIdsByBmcIps", vec![ForgeAdminCLI]);
        x.perm("IdentifyUuid", vec![ForgeAdminCLI]);
        x.perm("IdentifyMac", vec![ForgeAdminCLI]);
        x.perm("IdentifySerial", vec![ForgeAdminCLI, Machineatron]);
        x.perm("GetBMCMetaData", vec![Health, Ssh]);
        x.perm("UpdateBMCMetaData", vec![Machineatron]);
        x.perm("UpdateMachineCredentials", vec![]);
        x.perm("GetPxeInstructions", vec![Pxe, Machineatron]);
        x.perm("GetCloudInitInstructions", vec![Pxe]);
        x.perm("Echo", vec![]);
        x.perm("CreateTenant", vec![]);
        x.perm("FindTenant", vec![ForgeAdminCLI]);
        x.perm("UpdateTenant", vec![]);
        x.perm("CreateTenantKeyset", vec![SiteAgent]);
        x.perm("FindTenantKeysetIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindTenantKeysetsByIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindTenantKeyset", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateTenantKeyset", vec![SiteAgent]);
        x.perm("DeleteTenantKeyset", vec![SiteAgent]);
        x.perm("ValidateTenantPublicKey", vec![SiteAgent, Ssh]);
        x.perm("GetDpuSSHCredential", vec![ForgeAdminCLI]);
        x.perm("GetAllManagedHostNetworkStatus", vec![ForgeAdminCLI]);
        x.perm(
            "GetSiteExplorationReport",
            vec![ForgeAdminCLI, Machineatron],
        );
        x.perm("ClearSiteExplorationError", vec![ForgeAdminCLI]);
        x.perm("IsBmcInManagedHost", vec![ForgeAdminCLI]);
        x.perm("Explore", vec![ForgeAdminCLI]);
        x.perm("ReExploreEndpoint", vec![ForgeAdminCLI]);
        x.perm("FindExploredEndpointIds", vec![ForgeAdminCLI]);
        x.perm("FindExploredEndpointsByIds", vec![ForgeAdminCLI]);
        x.perm("FindExploredManagedHostIds", vec![ForgeAdminCLI]);
        x.perm("FindExploredManagedHostsByIds", vec![ForgeAdminCLI]);
        x.perm("AdminForceDeleteMachine", vec![ForgeAdminCLI, Machineatron]);
        x.perm("AdminListResourcePools", vec![ForgeAdminCLI]);
        x.perm("AdminGrowResourcePool", vec![ForgeAdminCLI]);
        x.perm("SetMaintenance", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("SetDynamicConfig", vec![ForgeAdminCLI, Machineatron]);
        x.perm("TriggerDpuReprovisioning", vec![ForgeAdminCLI]);
        x.perm("ListDpuWaitingForReprovisioning", vec![ForgeAdminCLI]);
        x.perm("GetDpuInfoList", vec![Agent]);
        x.perm("GetMachineBootOverride", vec![ForgeAdminCLI]);
        x.perm("SetMachineBootOverride", vec![ForgeAdminCLI]);
        x.perm("ClearMachineBootOverride", vec![ForgeAdminCLI]);
        x.perm("GetNetworkTopology", vec![ForgeAdminCLI]);
        x.perm("FindNetworkDevicesByDeviceIds", vec![ForgeAdminCLI]);
        x.perm("CreateCredential", vec![ForgeAdminCLI]);
        x.perm("DeleteCredential", vec![ForgeAdminCLI]);
        x.perm("GetRouteServers", vec![ForgeAdminCLI]);
        x.perm("AddRouteServers", vec![ForgeAdminCLI]);
        x.perm("RemoveRouteServers", vec![ForgeAdminCLI]);
        x.perm("ReplaceRouteServers", vec![]);
        x.perm("UpdateAgentReportedInventory", vec![Agent]);
        x.perm("UpdateInstancePhoneHomeLastContact", vec![Agent]);
        x.perm("SetHostUefiPassword", vec![ForgeAdminCLI]);
        x.perm("ClearHostUefiPassword", vec![ForgeAdminCLI]);
        x.perm("AddExpectedMachine", vec![ForgeAdminCLI]);
        x.perm("DeleteExpectedMachine", vec![ForgeAdminCLI]);
        x.perm("UpdateExpectedMachine", vec![ForgeAdminCLI]);
        x.perm("GetExpectedMachine", vec![ForgeAdminCLI]);
        x.perm("GetAllExpectedMachines", vec![ForgeAdminCLI]);
        x.perm("ReplaceAllExpectedMachines", vec![ForgeAdminCLI]);
        x.perm("DeleteAllExpectedMachines", vec![ForgeAdminCLI]);
        x.perm("GetAllExpectedMachinesLinked", vec![ForgeAdminCLI]);
        x.perm("AttestQuote", vec![Anonymous]);
        x.perm("CreateMeasurementBundle", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteMeasurementBundle", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("RenameMeasurementBundle", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateMeasurementBundle", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("ShowMeasurementBundle", vec![ForgeAdminCLI]);
        x.perm("ShowMeasurementBundles", vec![ForgeAdminCLI]);
        x.perm("ListMeasurementBundles", vec![ForgeAdminCLI]);
        x.perm("ListMeasurementBundleMachines", vec![ForgeAdminCLI]);
        x.perm("DeleteMeasurementJournal", vec![ForgeAdminCLI]);
        x.perm("ShowMeasurementJournal", vec![ForgeAdminCLI]);
        x.perm("ShowMeasurementJournals", vec![ForgeAdminCLI]);
        x.perm("ListMeasurementJournal", vec![ForgeAdminCLI]);
        x.perm("AttestCandidateMachine", vec![ForgeAdminCLI]);
        x.perm("ShowCandidateMachine", vec![ForgeAdminCLI]);
        x.perm("ShowCandidateMachines", vec![ForgeAdminCLI]);
        x.perm("ListCandidateMachines", vec![ForgeAdminCLI]);
        x.perm(
            "CreateMeasurementSystemProfile",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "DeleteMeasurementSystemProfile",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "RenameMeasurementSystemProfile",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm("ShowMeasurementSystemProfile", vec![ForgeAdminCLI]);
        x.perm("ShowMeasurementSystemProfiles", vec![ForgeAdminCLI]);
        x.perm("ListMeasurementSystemProfiles", vec![ForgeAdminCLI]);
        x.perm("ListMeasurementSystemProfileBundles", vec![ForgeAdminCLI]);
        x.perm("ListMeasurementSystemProfileMachines", vec![ForgeAdminCLI]);
        x.perm("CreateMeasurementReport", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteMeasurementReport", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("PromoteMeasurementReport", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("RevokeMeasurementReport", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("ShowMeasurementReportForId", vec![ForgeAdminCLI]);
        x.perm("ShowMeasurementReportsForMachine", vec![ForgeAdminCLI]);
        x.perm("ShowMeasurementReports", vec![ForgeAdminCLI]);
        x.perm("ListMeasurementReport", vec![ForgeAdminCLI]);
        x.perm("MatchMeasurementReport", vec![ForgeAdminCLI]);
        x.perm("ImportSiteMeasurements", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("ExportSiteMeasurements", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "AddMeasurementTrustedMachine",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "RemoveMeasurementTrustedMachine",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "AddMeasurementTrustedProfile",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "RemoveMeasurementTrustedProfile",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "ListMeasurementTrustedMachines",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "ListMeasurementTrustedProfiles",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm("ImportStorageCluster", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteStorageCluster", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("ListStorageCluster", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("GetStorageCluster", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateStorageCluster", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateStoragePool", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteStoragePool", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("ListStoragePool", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("GetStoragePool", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateStoragePool", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateStorageVolume", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteStorageVolume", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("ListStorageVolume", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("GetStorageVolume", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateStorageVolume", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateOsImage", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteOsImage", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("ListOsImage", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("GetOsImage", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateOsImage", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("RebootCompleted", vec![Machineatron, Scout]);
        x.perm("PersistValidationResult", vec![Scout]);
        x.perm("GetMachineValidationResults", vec![ForgeAdminCLI, Scout]);
        x.perm("MachineValidationCompleted", vec![Machineatron, Scout]);
        x.perm("MachineSetAutoUpdate", vec![ForgeAdminCLI]);
        x.perm(
            "GetMachineValidationExternalConfig",
            vec![ForgeAdminCLI, Scout],
        );
        x.perm(
            "AddUpdateMachineValidationExternalConfig",
            vec![ForgeAdminCLI],
        );
        x.perm("GetMachineValidationRuns", vec![ForgeAdminCLI]);
        x.perm("AdminBmcReset", vec![ForgeAdminCLI]);
        x.perm("AdminPowerControl", vec![ForgeAdminCLI]);
        x.perm("ForgeSetup", vec![ForgeAdminCLI]);
        x.perm("FetchForgeSetupStatus", vec![ForgeAdminCLI]);
        x.perm("OnDemandMachineValidation", vec![ForgeAdminCLI]);
        x.perm("TpmAddCaCert", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("TpmShowCaCerts", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("TpmShowUnmatchedEkCerts", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("TpmDeleteCaCert", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindTenantOrganizationIds", vec![SiteAgent]);
        x.perm("FindTenantsByOrganizationIds", vec![SiteAgent]);
        x.perm("FindMacAddressByBmcIp", vec![SiteAgent]);
        x.perm("BmcCredentialStatus", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "GetMachineValidationExternalConfigs",
            vec![ForgeAdminCLI, Scout, SiteAgent],
        );
        x.perm(
            "RemoveMachineValidationExternalConfig",
            vec![ForgeAdminCLI, Scout, SiteAgent],
        );
        x.perm(
            "GetMachineValidationTests",
            vec![ForgeAdminCLI, SiteAgent, Agent, Scout],
        );
        x.perm("AddMachineValidationTest", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "UpdateMachineValidationTest",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "MachineValidationTestVerfied",
            vec![ForgeAdminCLI, Scout, SiteAgent],
        );
        x.perm(
            "MachineValidationTestNextVersion",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "MachineValidationTestEnableDisableTest",
            vec![ForgeAdminCLI, SiteAgent, Scout],
        );
        x.perm("UpdateMachineValidationRun", vec![Scout, SiteAgent]);

        x
    }
    fn perm(&mut self, msg: &str, principals: Vec<RulePrincipal>) {
        self.perms
            .insert(msg.to_string(), RuleInfo::new(principals));
    }

    pub fn allowed_from_static(msg: &str, user_principals: &[crate::auth::Principal]) -> bool {
        INTERNAL_RBAC_RULES.allowed(msg, user_principals)
    }

    pub fn allowed(&self, msg: &str, user_principals: &[crate::auth::Principal]) -> bool {
        if let Some(perm_info) = self.perms.get(msg) {
            if user_principals.is_empty() {
                // No proper cert presented, but we will allow stuff that allows just Anonymous
                return perm_info.principals.as_slice() == [Principal::Anonymous];
            }
            user_principals.iter().any(|user_principal| {
                perm_info
                    .principals
                    .iter()
                    .any(|perm_principal| user_principal.is_proper_subset_of(perm_principal))
            })
        } else {
            false
        }
    }
}

impl Default for InternalRBACRules {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct RuleInfo {
    principals: Vec<crate::auth::Principal>,
}

impl RuleInfo {
    pub fn new(principals: Vec<RulePrincipal>) -> Self {
        Self {
            principals: principals
                .iter()
                .map(|x| match *x {
                    RulePrincipal::ForgeAdminCLI => Principal::ExternalUser(ExternalUserInfo::new(
                        None,
                        "Invalid".to_string(),
                        None,
                    )),
                    RulePrincipal::Machineatron => {
                        Principal::SpiffeServiceIdentifier("machine-a-tron".to_string())
                    }
                    RulePrincipal::SiteAgent => {
                        Principal::SpiffeServiceIdentifier("elektra-site-agent".to_string())
                    }
                    RulePrincipal::Agent => Principal::SpiffeMachineIdentifier("".to_string()),
                    RulePrincipal::Scout => Principal::SpiffeMachineIdentifier("".to_string()),
                    RulePrincipal::Dns => {
                        Principal::SpiffeServiceIdentifier("carbide-dns".to_string())
                    }
                    RulePrincipal::Dhcp => {
                        Principal::SpiffeServiceIdentifier("carbide-dhcp".to_string())
                    }
                    RulePrincipal::Ssh => {
                        Principal::SpiffeServiceIdentifier("carbide-ssh-console".to_string())
                    }
                    RulePrincipal::Pxe => {
                        Principal::SpiffeServiceIdentifier("carbide-pxe".to_string())
                    }
                    RulePrincipal::Health => {
                        Principal::SpiffeServiceIdentifier("carbide-hardware-health".to_string())
                    }
                    RulePrincipal::Anonymous => Principal::Anonymous,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod rbac_rule_tests {
    use std::{
        fs::File,
        io::{BufRead, BufReader},
    };

    use super::*;
    use crate::auth::Principal;

    #[test]
    fn rbac_rule_tests() -> Result<(), eyre::Report> {
        assert!(InternalRBACRules::allowed_from_static(
            "Version",
            &[Principal::TrustedCertificate]
        ));
        assert!(InternalRBACRules::allowed_from_static(
            "GetStoragePool",
            &[Principal::ExternalUser(ExternalUserInfo::new(
                None,
                "any".to_string(),
                None
            ))]
        ));
        assert!(!InternalRBACRules::allowed_from_static(
            "GetStoragePool",
            &[Principal::SpiffeMachineIdentifier("foo".to_string())]
        ));
        assert!(InternalRBACRules::allowed_from_static(
            "ReportForgeScoutError",
            &[Principal::SpiffeMachineIdentifier("foo".to_string())]
        ));
        assert!(!InternalRBACRules::allowed_from_static(
            "ReportForgeScoutError",
            &[Principal::ExternalUser(ExternalUserInfo::new(
                None,
                "any".to_string(),
                None
            ))]
        ));
        assert!(InternalRBACRules::allowed_from_static(
            "GetCloudInitInstructions",
            &[Principal::SpiffeServiceIdentifier(
                "carbide-pxe".to_string()
            )]
        ));
        assert!(!InternalRBACRules::allowed_from_static(
            "GetCloudInitInstructions",
            &[Principal::SpiffeServiceIdentifier(
                "carbide-dns".to_string()
            )]
        ));
        assert!(!InternalRBACRules::allowed_from_static(
            "GetCloudInitInstructions",
            &[Principal::ExternalUser(ExternalUserInfo::new(
                None,
                "any".to_string(),
                None
            ))]
        ));
        assert!(InternalRBACRules::allowed_from_static(
            "CreateVpc",
            &[Principal::SpiffeServiceIdentifier(
                "machine-a-tron".to_string()
            )]
        ));
        assert!(!InternalRBACRules::allowed_from_static(
            "CreateVpc",
            &[Principal::SpiffeServiceIdentifier(
                "carbide-dns".to_string()
            )]
        ));

        assert!(InternalRBACRules::allowed_from_static(
            "CreateTenantKeyset",
            &[Principal::SpiffeServiceIdentifier(
                "elektra-site-agent".to_string()
            )]
        ));
        assert!(InternalRBACRules::allowed_from_static(
            "FindNetworkSegments",
            &[
                Principal::SpiffeServiceIdentifier("machine-a-tron".to_string()),
                Principal::TrustedCertificate
            ]
        ));

        assert!(InternalRBACRules::allowed_from_static(
            "DiscoverMachine",
            &[]
        ));

        Ok(())
    }
    #[test]
    fn all_requests_listed() -> Result<(), eyre::Report> {
        let mut messages = vec![];
        let proto = File::open("../rpc/proto/forge.proto")?;
        let reader = BufReader::new(proto);
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.starts_with("rpc") {
                let mut name = line.strip_prefix("rpc").unwrap_or("why").trim().to_string();
                let offset = name.find("(").unwrap_or(name.len());
                name.replace_range(offset.., "");
                messages.push(name.trim().to_string());
            }
        }
        if messages.is_empty() {
            panic!("Parsing failed, no messages found")
        }
        let rules = InternalRBACRules::new();
        let mut missing = vec![];
        for msg in messages {
            if !rules.perms.contains_key(&msg) {
                missing.push(msg);
            }
        }
        if !missing.is_empty() {
            panic!("GRPC messages missing RBAC permissions: {:?}", missing);
        }
        Ok(())
    }
}
