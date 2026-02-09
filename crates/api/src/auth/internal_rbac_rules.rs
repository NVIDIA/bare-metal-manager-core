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

use std::collections::HashMap;
use std::sync::LazyLock;

use super::ExternalUserInfo;
use crate::auth::Principal;

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
    SshRs,
    Health,
    Pxe,
    Rla,
    MaintenanceJobs,
    DsxExchangeConsumer,
    Anonymous, // Permitted for everything
}
use self::RulePrincipal::{
    Agent, Anonymous, Dhcp, Dns, DsxExchangeConsumer, ForgeAdminCLI, Health, Machineatron,
    MaintenanceJobs, Pxe, Rla, Scout, SiteAgent, Ssh, SshRs,
};

impl InternalRBACRules {
    pub fn new() -> Self {
        let mut x = Self {
            perms: HashMap::default(),
        };

        // Add additional permissions to the list below.
        x.perm("Version", vec![Anonymous]);
        x.perm("CreateDomain", vec![]);
        x.perm("CreateDomainLegacy", vec![]);
        x.perm("UpdateDomainLegacy", vec![]);
        x.perm("DeleteDomainLegacy", vec![]);
        x.perm("FindDomainLegacy", vec![ForgeAdminCLI]);
        x.perm("UpdateDomain", vec![]);
        x.perm("DeleteDomain", vec![]);
        x.perm("FindDomain", vec![ForgeAdminCLI]);
        x.perm("CreateVpc", vec![SiteAgent, Machineatron]);
        x.perm("UpdateVpc", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateVpcVirtualization", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteVpc", vec![Machineatron, SiteAgent]);
        x.perm("FindVpcIds", vec![SiteAgent, ForgeAdminCLI, Machineatron]);
        x.perm("FindVpcsByIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateVpcPrefix", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("SearchVpcPrefixes", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("GetVpcPrefixes", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateVpcPrefix", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteVpcPrefix", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("GetAllDpaInterfaceIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindDpaInterfacesByIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateDpaInterface", vec![]);
        x.perm("DeleteDpaInterface", vec![]);
        x.perm("SetDpaNetworkObservationStatus", vec![]);
        x.perm(
            "FindNetworkSegmentIds",
            vec![ForgeAdminCLI, Machineatron, SiteAgent],
        );
        x.perm(
            "FindNetworkSegmentsByIds",
            vec![ForgeAdminCLI, Machineatron, SiteAgent],
        );
        x.perm("CreateNetworkSegment", vec![Machineatron, SiteAgent]);
        x.perm("DeleteNetworkSegment", vec![Machineatron, SiteAgent]);
        x.perm("NetworkSegmentsForVpc", vec![]);
        x.perm("FindIBPartitionIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindIBPartitionsByIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateIBPartition", vec![SiteAgent]);
        x.perm("DeleteIBPartition", vec![SiteAgent]);
        x.perm("IBPartitionsForTenant", vec![]);
        x.perm("FindIBFabricIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "AllocateInstance",
            vec![ForgeAdminCLI, Machineatron, SiteAgent],
        );
        x.perm(
            "AllocateInstances",
            vec![ForgeAdminCLI, Machineatron, SiteAgent],
        );
        x.perm("ReleaseInstance", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateInstanceOperatingSystem", vec![SiteAgent]);
        x.perm("UpdateInstanceConfig", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindInstanceIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "FindInstancesByIds",
            vec![ForgeAdminCLI, SiteAgent, Ssh, SshRs],
        );
        x.perm(
            "FindInstanceByMachineID",
            vec![ForgeAdminCLI, Agent, SiteAgent],
        );
        x.perm("RecordObservedInstanceNetworkStatus", vec![]);
        x.perm(
            "GetManagedHostNetworkConfig",
            vec![ForgeAdminCLI, Agent, Machineatron, SiteAgent],
        );
        x.perm("RecordDpuNetworkStatus", vec![Agent, Machineatron]);
        x.perm("RecordHardwareHealthReport", vec![Health]);
        x.perm("RecordLogParserHealthReport", vec![Health, Ssh, SshRs]);
        x.perm("GetHardwareHealthReport", vec![]);
        x.perm("ListHealthReportOverrides", vec![ForgeAdminCLI]);
        x.perm("InsertHealthReportOverride", vec![ForgeAdminCLI]);
        x.perm("RemoveHealthReportOverride", vec![ForgeAdminCLI]);
        x.perm(
            "ListRackHealthReportOverrides",
            vec![ForgeAdminCLI, DsxExchangeConsumer],
        );
        x.perm(
            "InsertRackHealthReportOverride",
            vec![ForgeAdminCLI, DsxExchangeConsumer],
        );
        x.perm(
            "RemoveRackHealthReportOverride",
            vec![ForgeAdminCLI, DsxExchangeConsumer],
        );
        x.perm("DpuAgentUpgradeCheck", vec![Scout]);
        x.perm("DpuAgentUpgradePolicyAction", vec![ForgeAdminCLI]);
        x.perm("LookupRecord", vec![Dns]);
        x.perm("LookupRecordLegacy", vec![Dns]);
        x.perm("GetAllDomainMetadata", vec![Dns]);
        x.perm("GetAllDomains", vec![Dns]);
        x.perm("InvokeInstancePower", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("ForgeAgentControl", vec![Machineatron, Scout]);
        x.perm("DiscoverMachine", vec![Anonymous]);
        x.perm("RenewMachineCertificate", vec![Agent]);
        x.perm("DiscoveryCompleted", vec![Machineatron, Scout]);
        x.perm("CleanupMachineCompleted", vec![Machineatron, Scout]);
        x.perm("ReportForgeScoutError", vec![Scout]);
        x.perm("DiscoverDhcp", vec![Dhcp, Machineatron]);
        x.perm("FindInterfaces", vec![ForgeAdminCLI]);
        x.perm("DeleteInterface", vec![ForgeAdminCLI]);
        x.perm("FindIpAddress", vec![ForgeAdminCLI]);
        x.perm(
            "FindMachineIds",
            vec![
                ForgeAdminCLI,
                Machineatron,
                Health,
                SiteAgent,
                Ssh,
                SshRs,
                Rla,
            ],
        );
        x.perm(
            "FindMachinesByIds",
            vec![
                ForgeAdminCLI,
                Machineatron,
                Health,
                SiteAgent,
                Ssh,
                SshRs,
                Rla,
            ],
        );
        x.perm("FindConnectedDevicesByDpuMachineIds", vec![ForgeAdminCLI]);
        x.perm("FindMachineIdsByBmcIps", vec![ForgeAdminCLI, Rla]);
        x.perm("FindMachineHealthHistories", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindMachineStateHistories", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("IdentifyUuid", vec![ForgeAdminCLI]);
        x.perm("IdentifyMac", vec![ForgeAdminCLI]);
        x.perm("IdentifySerial", vec![ForgeAdminCLI, Machineatron, Rla]);
        x.perm("GetBMCMetaData", vec![Health, Ssh, SshRs]);
        x.perm("UpdateBMCMetaData", vec![Machineatron]);
        x.perm("UpdateMachineCredentials", vec![]);
        x.perm("GetPxeInstructions", vec![Pxe, Machineatron]);
        x.perm("GetCloudInitInstructions", vec![Pxe]);
        x.perm("Echo", vec![Dhcp]);
        x.perm("CreateTenant", vec![SiteAgent]);
        x.perm("FindTenant", vec![SiteAgent, ForgeAdminCLI]);
        x.perm("UpdateTenant", vec![SiteAgent, ForgeAdminCLI]);
        x.perm("CreateTenantKeyset", vec![SiteAgent]);
        x.perm("FindTenantKeysetIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindTenantKeysetsByIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateTenantKeyset", vec![SiteAgent]);
        x.perm("DeleteTenantKeyset", vec![SiteAgent]);
        x.perm("ValidateTenantPublicKey", vec![SiteAgent, Ssh, SshRs]);
        x.perm("GetDpuSSHCredential", vec![ForgeAdminCLI]);
        x.perm("GetAllManagedHostNetworkStatus", vec![ForgeAdminCLI]);
        x.perm(
            "GetSiteExplorationReport",
            vec![ForgeAdminCLI, Machineatron],
        );
        x.perm("ClearSiteExplorationError", vec![ForgeAdminCLI]);
        x.perm("IsBmcInManagedHost", vec![ForgeAdminCLI]);
        x.perm("Explore", vec![ForgeAdminCLI, Rla]);
        x.perm("ReExploreEndpoint", vec![ForgeAdminCLI, Rla]);
        x.perm("DeleteExploredEndpoint", vec![ForgeAdminCLI]);
        x.perm("PauseExploredEndpointRemediation", vec![ForgeAdminCLI]);
        x.perm("FindExploredEndpointIds", vec![ForgeAdminCLI, Rla]);
        x.perm("FindExploredEndpointsByIds", vec![ForgeAdminCLI, Rla]);
        x.perm("FindExploredManagedHostIds", vec![ForgeAdminCLI, Rla]);
        x.perm("FindExploredManagedHostsByIds", vec![ForgeAdminCLI, Rla]);
        x.perm("AdminForceDeleteMachine", vec![ForgeAdminCLI, Machineatron]);
        x.perm("AdminListResourcePools", vec![ForgeAdminCLI]);
        x.perm("AdminGrowResourcePool", vec![ForgeAdminCLI]);
        x.perm("SetMaintenance", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("SetDynamicConfig", vec![ForgeAdminCLI, Machineatron]);
        x.perm("TriggerDpuReprovisioning", vec![ForgeAdminCLI]);
        x.perm("TriggerHostReprovisioning", vec![ForgeAdminCLI, Rla]);
        x.perm("ListDpuWaitingForReprovisioning", vec![ForgeAdminCLI]);
        x.perm("MarkManualFirmwareUpgradeComplete", vec![ForgeAdminCLI]);
        x.perm(
            "ListHostsWaitingForReprovisioning",
            vec![ForgeAdminCLI, Rla],
        );
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
        x.perm("AddExpectedMachine", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteExpectedMachine", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateExpectedMachine", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateExpectedMachines", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateExpectedMachines", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("GetExpectedMachine", vec![ForgeAdminCLI, Rla]);
        x.perm(
            "GetAllExpectedMachines",
            vec![ForgeAdminCLI, SiteAgent, Rla],
        );
        x.perm("ReplaceAllExpectedMachines", vec![ForgeAdminCLI]);
        x.perm("DeleteAllExpectedMachines", vec![ForgeAdminCLI]);
        x.perm(
            "GetAllExpectedMachinesLinked",
            vec![ForgeAdminCLI, SiteAgent, Rla],
        );
        x.perm("AttestQuote", vec![Anonymous]);
        x.perm("CreateMeasurementBundle", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteMeasurementBundle", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("RenameMeasurementBundle", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateMeasurementBundle", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("ShowMeasurementBundle", vec![ForgeAdminCLI]);
        x.perm("ShowMeasurementBundles", vec![ForgeAdminCLI]);
        x.perm("ListMeasurementBundles", vec![ForgeAdminCLI]);
        x.perm("ListMeasurementBundleMachines", vec![ForgeAdminCLI]);
        x.perm("FindClosestBundleMatch", vec![ForgeAdminCLI]);
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
        x.perm("ListAttestationSummary", vec![SiteAgent]);
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
        x.perm("CreateRackFirmware", vec![ForgeAdminCLI]);
        x.perm("DeleteRackFirmware", vec![ForgeAdminCLI]);
        x.perm("ListRackFirmware", vec![ForgeAdminCLI]);
        x.perm("GetRackFirmware", vec![ForgeAdminCLI]);
        x.perm("ApplyRackFirmware", vec![ForgeAdminCLI]);
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
        x.perm("AdminPowerControl", vec![ForgeAdminCLI, Rla]);
        x.perm("DisableSecureBoot", vec![ForgeAdminCLI]);
        x.perm("MachineSetup", vec![ForgeAdminCLI]);
        x.perm("SetDpuFirstBootOrder", vec![ForgeAdminCLI]);
        x.perm("OnDemandMachineValidation", vec![ForgeAdminCLI]);
        x.perm("TpmAddCaCert", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("TpmShowCaCerts", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("TpmShowUnmatchedEkCerts", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("TpmDeleteCaCert", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("RedfishListActions", vec![ForgeAdminCLI]);
        x.perm("RedfishCreateAction", vec![ForgeAdminCLI]);
        x.perm("RedfishApproveAction", vec![ForgeAdminCLI]);
        x.perm("RedfishApplyAction", vec![ForgeAdminCLI]);
        x.perm("RedfishCancelAction", vec![ForgeAdminCLI]);
        x.perm("FindTenantOrganizationIds", vec![SiteAgent, ForgeAdminCLI]);
        x.perm(
            "FindTenantsByOrganizationIds",
            vec![SiteAgent, ForgeAdminCLI],
        );
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
        x.perm("FindInstanceTypeIds", vec![SiteAgent, ForgeAdminCLI]);
        x.perm("FindInstanceTypesByIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateInstanceType", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateInstanceType", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteInstanceType", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "AssociateMachinesWithInstanceType",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "RemoveMachineInstanceTypeAssociation",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm("RedfishBrowse", vec![ForgeAdminCLI]);
        x.perm("UfmBrowse", vec![ForgeAdminCLI]);
        x.perm("NmxmBrowse", vec![ForgeAdminCLI]);
        x.perm("UpdateMachineMetadata", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateNetworkSecurityGroup", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "FindNetworkSecurityGroupIds",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "FindNetworkSecurityGroupsByIds",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm("UpdateNetworkSecurityGroup", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteNetworkSecurityGroup", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "GetNetworkSecurityGroupPropagationStatus",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "GetNetworkSecurityGroupAttachments",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "GetDesiredFirmwareVersions",
            vec![ForgeAdminCLI, Machineatron],
        );
        x.perm("CreateSku", vec![ForgeAdminCLI]);
        x.perm("GenerateSkuFromMachine", vec![ForgeAdminCLI]);
        x.perm("AssignSkuToMachine", vec![ForgeAdminCLI]);
        x.perm("VerifySkuForMachine", vec![ForgeAdminCLI]);
        x.perm("RemoveSkuAssociation", vec![ForgeAdminCLI]);
        x.perm("GetAllSkuIds", vec![ForgeAdminCLI, SiteAgent, Rla]);
        x.perm("FindSkusByIds", vec![ForgeAdminCLI, SiteAgent, Rla]);
        x.perm("DeleteSku", vec![ForgeAdminCLI]);
        x.perm("UpdateSkuMetadata", vec![ForgeAdminCLI]);
        x.perm("UpdateMachineHardwareInfo", vec![ForgeAdminCLI]);
        x.perm("ReplaceSku", vec![ForgeAdminCLI]);
        x.perm(
            "GetManagedHostQuarantineState",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "SetManagedHostQuarantineState",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "ClearManagedHostQuarantineState",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm("CreateVpcPeering", vec![ForgeAdminCLI]);
        x.perm("FindVpcPeeringIds", vec![ForgeAdminCLI]);
        x.perm("FindVpcPeeringsByIds", vec![ForgeAdminCLI]);
        x.perm("DeleteVpcPeering", vec![ForgeAdminCLI]);
        x.perm("ResetHostReprovisioning", vec![ForgeAdminCLI, Rla]);
        x.perm("CopyBfbToDpuRshim", vec![ForgeAdminCLI]);
        x.perm("GetPowerOptions", vec![ForgeAdminCLI, SiteAgent, Rla]);
        x.perm("UpdatePowerOption", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CreateBmcUser", vec![ForgeAdminCLI]);
        x.perm("DeleteBmcUser", vec![ForgeAdminCLI]);
        x.perm("SetFirmwareUpdateTimeWindow", vec![ForgeAdminCLI, Rla]);
        x.perm("ListHostFirmware", vec![ForgeAdminCLI, Rla]);
        x.perm("EnableInfiniteBoot", vec![ForgeAdminCLI]);
        x.perm("IsInfiniteBootEnabled", vec![ForgeAdminCLI]);
        x.perm("Lockdown", vec![ForgeAdminCLI]);
        x.perm("LockdownStatus", vec![ForgeAdminCLI]);
        x.perm(
            "PublishMlxDeviceReport",
            vec![Agent, Scout, Machineatron, ForgeAdminCLI],
        );
        x.perm(
            "PublishMlxObservationReport",
            vec![Agent, Scout, Machineatron, ForgeAdminCLI],
        );
        x.perm("TrimTable", vec![ForgeAdminCLI, MaintenanceJobs]);
        x.perm("CreateRemediation", vec![ForgeAdminCLI]);
        x.perm("ApproveRemediation", vec![ForgeAdminCLI]);
        x.perm("RevokeRemediation", vec![ForgeAdminCLI]);
        x.perm("EnableRemediation", vec![ForgeAdminCLI]);
        x.perm("DisableRemediation", vec![ForgeAdminCLI]);
        x.perm("FindRemediationIds", vec![ForgeAdminCLI]);
        x.perm("FindRemediationsByIds", vec![ForgeAdminCLI]);
        x.perm("FindAppliedRemediations", vec![ForgeAdminCLI]);
        x.perm("FindAppliedRemediationIds", vec![ForgeAdminCLI]);
        x.perm("GetNextRemediationForMachine", vec![Agent]);
        x.perm("RemediationApplied", vec![Agent]);
        x.perm("DetermineMachineIngestionState", vec![ForgeAdminCLI, Rla]);
        x.perm("AllowIngestionAndPowerOn", vec![ForgeAdminCLI, Rla]);
        x.perm("SetPrimaryDpu", vec![ForgeAdminCLI]);
        x.perm("CreateDpuExtensionService", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("UpdateDpuExtensionService", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("DeleteDpuExtensionService", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindDpuExtensionServiceIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "FindDpuExtensionServicesByIds",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "GetDpuExtensionServiceVersionsInfo",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "FindInstancesByDpuExtensionService",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm("TriggerMachineAttestation", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("CancelMachineAttestation", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "FindMachineIdsUnderAttestation",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "FindMachinesUnderAttestation",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm("FindPowerShelves", vec![ForgeAdminCLI, Machineatron, Rla]);
        x.perm("CreatePowerShelf", vec![ForgeAdminCLI, Machineatron]);
        x.perm("DeletePowerShelf", vec![ForgeAdminCLI, Machineatron]);
        x.perm("AddExpectedPowerShelf", vec![ForgeAdminCLI, Machineatron]);
        x.perm(
            "DeleteExpectedPowerShelf",
            vec![ForgeAdminCLI, Machineatron],
        );
        x.perm(
            "UpdateExpectedPowerShelf",
            vec![ForgeAdminCLI, Machineatron],
        );
        x.perm(
            "GetExpectedPowerShelf",
            vec![ForgeAdminCLI, Machineatron, Rla],
        );
        x.perm(
            "GetAllExpectedPowerShelves",
            vec![ForgeAdminCLI, Machineatron, Rla],
        );
        x.perm(
            "ReplaceAllExpectedPowerShelves",
            vec![ForgeAdminCLI, Machineatron],
        );
        x.perm(
            "DeleteAllExpectedPowerShelves",
            vec![ForgeAdminCLI, Machineatron],
        );
        x.perm(
            "GetAllExpectedPowerShelvesLinked",
            vec![ForgeAdminCLI, Machineatron, Rla],
        );
        x.perm(
            "FindPowerShelfStateHistories",
            vec![ForgeAdminCLI, Machineatron, Rla],
        );
        x.perm(
            "FindSwitches",
            vec![ForgeAdminCLI, Machineatron, Rla, Health],
        );
        x.perm("CreateSwitch", vec![ForgeAdminCLI, Machineatron]);
        x.perm("DeleteSwitch", vec![ForgeAdminCLI, Machineatron]);
        x.perm("AddExpectedSwitch", vec![ForgeAdminCLI, Machineatron]);
        x.perm("DeleteExpectedSwitch", vec![ForgeAdminCLI, Machineatron]);
        x.perm("UpdateExpectedSwitch", vec![ForgeAdminCLI, Machineatron]);
        x.perm("GetExpectedSwitch", vec![ForgeAdminCLI, Machineatron, Rla]);
        x.perm(
            "GetAllExpectedSwitches",
            vec![ForgeAdminCLI, Machineatron, Rla],
        );
        x.perm(
            "ReplaceAllExpectedSwitches",
            vec![ForgeAdminCLI, Machineatron],
        );
        x.perm(
            "DeleteAllExpectedSwitches",
            vec![ForgeAdminCLI, Machineatron],
        );
        x.perm(
            "GetAllExpectedSwitchesLinked",
            vec![ForgeAdminCLI, Machineatron, Rla],
        );
        x.perm(
            "FindSwitchStateHistories",
            vec![ForgeAdminCLI, Machineatron, Rla],
        );
        x.perm("GetRack", vec![ForgeAdminCLI, Rla]);
        x.perm("DeleteRack", vec![ForgeAdminCLI, Rla]);
        x.perm("RackManagerCall", vec![ForgeAdminCLI]);
        x.perm("ScoutStream", vec![Scout]);
        x.perm("ScoutStreamShowConnections", vec![ForgeAdminCLI]);
        x.perm("ScoutStreamDisconnect", vec![ForgeAdminCLI]);
        x.perm("ScoutStreamPing", vec![ForgeAdminCLI]);
        x.perm("MlxAdminProfileSync", vec![ForgeAdminCLI]);
        x.perm("MlxAdminProfileShow", vec![ForgeAdminCLI]);
        x.perm("MlxAdminProfileCompare", vec![ForgeAdminCLI]);
        x.perm("MlxAdminProfileList", vec![ForgeAdminCLI]);
        x.perm("MlxAdminLockdownLock", vec![ForgeAdminCLI]);
        x.perm("MlxAdminLockdownUnlock", vec![ForgeAdminCLI]);
        x.perm("MlxAdminLockdownStatus", vec![ForgeAdminCLI]);
        x.perm("MlxAdminShowDevice", vec![ForgeAdminCLI]);
        x.perm("MlxAdminShowMachine", vec![ForgeAdminCLI]);
        x.perm("MlxAdminRegistryList", vec![ForgeAdminCLI]);
        x.perm("MlxAdminRegistryShow", vec![ForgeAdminCLI]);
        x.perm("MlxAdminConfigQuery", vec![ForgeAdminCLI]);
        x.perm("MlxAdminConfigSet", vec![ForgeAdminCLI]);
        x.perm("MlxAdminConfigSync", vec![ForgeAdminCLI]);
        x.perm("MlxAdminConfigCompare", vec![ForgeAdminCLI]);
        x.perm("FindNVLinkPartitionIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("FindNVLinkPartitionsByIds", vec![ForgeAdminCLI, SiteAgent]);
        x.perm("NVLinkPartitionsForTenant", vec![ForgeAdminCLI, SiteAgent]);
        x.perm(
            "FindNVLinkLogicalPartitionIds",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "FindNVLinkLogicalPartitionsByIds",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "CreateNVLinkLogicalPartition",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "UpdateNVLinkLogicalPartition",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "DeleteNVLinkLogicalPartition",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "NVLinkLogicalPartitionsForTenant",
            vec![ForgeAdminCLI, SiteAgent],
        );
        x.perm(
            "GetMachinePositionInfo",
            vec![ForgeAdminCLI, SiteAgent, Rla],
        );
        x.perm("ModifyDPFState", vec![ForgeAdminCLI]);
        x.perm("GetDPFState", vec![ForgeAdminCLI]);
        x.perm("UpdateMachineNvLinkInfo", vec![ForgeAdminCLI]);
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
                    RulePrincipal::SshRs => {
                        Principal::SpiffeServiceIdentifier("carbide-ssh-console-rs".to_string())
                    }
                    RulePrincipal::Pxe => {
                        Principal::SpiffeServiceIdentifier("carbide-pxe".to_string())
                    }
                    RulePrincipal::Health => {
                        Principal::SpiffeServiceIdentifier("carbide-hardware-health".to_string())
                    }
                    RulePrincipal::Rla => {
                        Principal::SpiffeServiceIdentifier("carbide-rla".to_string())
                    }
                    RulePrincipal::MaintenanceJobs => {
                        Principal::SpiffeServiceIdentifier("carbide-maintenance-jobs".to_string())
                    }
                    RulePrincipal::DsxExchangeConsumer => Principal::SpiffeServiceIdentifier(
                        "carbide-dsx-exchange-consumer".to_string(),
                    ),
                    RulePrincipal::Anonymous => Principal::Anonymous,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod rbac_rule_tests {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    use super::*;
    use crate::auth::Principal;

    fn ensure_identical_permissions(princ_a: &Principal, princ_b: &Principal) {
        for (rule_name, rule) in &INTERNAL_RBAC_RULES.perms {
            if rule.principals.contains(princ_a) {
                assert!(
                    rule.principals.contains(princ_b),
                    "{} RBAC rule allows {} but not {}",
                    rule_name,
                    princ_a.as_identifier(),
                    princ_b.as_identifier(),
                );
            } else {
                assert!(
                    !rule.principals.contains(princ_b),
                    "{} RBAC rule rejects {} but allows {}",
                    rule_name,
                    princ_a.as_identifier(),
                    princ_b.as_identifier(),
                );
            }

            if rule.principals.contains(princ_b) {
                assert!(
                    rule.principals.contains(princ_a),
                    "{} RBAC rule allows {} but not {}",
                    rule_name,
                    princ_b.as_identifier(),
                    princ_a.as_identifier(),
                );
            } else {
                assert!(
                    !rule.principals.contains(princ_a),
                    "{} RBAC rule rejects {} but allows {}",
                    rule_name,
                    princ_b.as_identifier(),
                    princ_a.as_identifier(),
                );
            }
        }
    }

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
            "FindNetworkSegmentsByIds",
            &[
                Principal::SpiffeServiceIdentifier("machine-a-tron".to_string()),
                Principal::TrustedCertificate
            ]
        ));

        assert!(InternalRBACRules::allowed_from_static(
            "DiscoverMachine",
            &[]
        ));

        assert!(InternalRBACRules::allowed_from_static(
            "TrimTable",
            &[Principal::SpiffeServiceIdentifier(
                "carbide-maintenance-jobs".to_string()
            )]
        ));

        // Ensure Ssh and SshRs both have identical permissions. (ssh-console-rs is a rust rewrite
        // of ssh-console, and to keep things straightforward, it has its own set of DNS names,
        // SPIFFE identifiers, etc. We don't want to play any tricks by reusing principals here, so
        // we gotta list both, until we've fully migrated to ssh-console-rs.)
        ensure_identical_permissions(
            &Principal::SpiffeServiceIdentifier("carbide-ssh-console".to_string()),
            &Principal::SpiffeServiceIdentifier("carbide-ssh-console-rs".to_string()),
        );

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
            panic!("GRPC messages missing RBAC permissions: {missing:?}");
        }
        Ok(())
    }
}
