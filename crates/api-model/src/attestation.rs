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
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(FromRow, Debug)]
pub struct EkCertVerificationStatus {
    pub ek_sha256: Vec<u8>,
    pub serial_num: String,
    pub signing_ca_found: bool,
    pub issuer: Vec<u8>,
    pub issuer_access_info: Option<String>,
    pub machine_id: MachineId,
    // pub ca_id: Option<i32>, // currently unused
}

#[derive(FromRow, Debug, sqlx::Encode)]
pub struct SecretAkPub {
    pub secret: Vec<u8>,
    pub ak_pub: Vec<u8>,
}

#[derive(FromRow, Debug, sqlx::Encode)]
pub struct TpmCaCert {
    pub id: i32,
    pub not_valid_before: DateTime<Utc>,
    pub not_valid_after: DateTime<Utc>,
    #[sqlx(default)]
    pub ca_cert_der: Vec<u8>,
    pub cert_subject: Vec<u8>,
}

/// Model for SPDM attestation via Redfish
pub mod spdm {
    use std::collections::HashMap;
    use std::fmt::Display;
    use std::str::FromStr;

    use config_version::ConfigVersion;
    use itertools::Itertools;
    use libredfish::model::component_integrity::{CaCertificate, ComponentIntegrity, Evidence};
    use nras::{NrasError, NrasVerifierClient, ProcessedAttestationOutcome, RawAttestationOutcome};
    use serde::{Deserialize, Serialize};
    use sqlx::Row;
    use sqlx::postgres::PgRow;

    use super::*;
    use crate::bmc_info::BmcInfo;
    use crate::controller_outcome::PersistentStateHandlerOutcome;

    /// A SPDM machine and components snapshot.
    /// The `Snapshot` struct is designed to store a snapshot of the machine and its associated devices.
    /// If the devices are unknown or if attestation is not yet triggered, the `device` field will be `None`.
    /// This additional complexity is necessary due to preprocessing requirements.
    /// In managed-host or other state machine models, data rows (such as machines and network segments) are pre-populated.
    /// In contrast, the attestation state machine must dynamically fetch and update devices/components within the database.
    /// This introduces an extra layer of preprocessing.
    /// The goal is to treat each device as an independent entity for parallel processing while maintaining connections
    /// to advance the machine to its next major state. The managed-host model (comprising the host and connected DPUs)
    /// is not suitable here because it typically handles only 2 DPUs in sequence and halts if any DPU modifies its state.
    /// Conversely, each machine in the attestation state machine may have multiple components like GPUs, CPUs, BMCs, FPGAs,
    /// etc., potentially numbering up to 8-10 components once Carbide supports attestation for all components.
    /// Therefore, the managed-host model is not scalable for this use case.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SpdmMachineSnapshot {
        pub machine: SpdmMachineAttestation,
        pub device: Option<SpdmMachineDeviceAttestation>,
        pub devices_state: HashMap<String, AttestationDeviceState>,
        pub bmc_info: BmcInfo,
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SpdmMachineDetails {
        pub machine: SpdmMachineAttestation,
        pub devices: Vec<SpdmMachineDeviceAttestation>,
    }

    #[derive(Copy, Debug, Eq, Hash, PartialEq, Clone, Serialize, Deserialize, sqlx::Type)]
    #[sqlx(type_name = "spdm_attestation_status_t")]
    #[sqlx(rename_all = "snake_case")]
    #[serde(rename_all = "snake_case")]
    pub enum SpdmAttestationStatus {
        NotStarted,
        Started,
        NotSupported,
        DeviceListMismatch,
        Completed,
    }

    /// A data model to keep attestation request and cancellation received from managed-host state machine.
    /// This model also stores the running status of a request.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SpdmMachineAttestation {
        // Machine id. Host and DPU are treated at separate entity here.
        pub machine_id: MachineId,
        // If requested_at > started_at, indicates that a new Attestation Request is received.
        // The request can be received via managed-host state machine or admin-cli.
        pub requested_at: DateTime<Utc>,
        // When state machine picks this record first time, it updates the started_at field.
        pub started_at: Option<DateTime<Utc>>,
        // If managed-host state machine decides to cancel the attestation (e.g. taking too much
        // time), it will update this field. if requested_at < canceled_at, means cancellation
        // request is received.
        pub canceled_at: Option<DateTime<Utc>>,
        // Attestation major (machine's) state
        pub state: AttestationState,
        // State version will increase
        pub state_version: ConfigVersion,
        /// The result of the last attempt to change state
        pub state_outcome: Option<PersistentStateHandlerOutcome>,
        // If attestation is started, completed or not supported
        pub attestation_status: SpdmAttestationStatus,
    }

    /// Data model to store progress of attestation related to a device/component of a machine BMC (e.g.
    /// GPU, CPU, BMC, CX7)
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SpdmMachineDeviceAttestation {
        // Host or DPU's machine id
        pub machine_id: MachineId,
        // Component/device of the machine (GPU, CPU, BMC)
        // e.g. HGX_IRoT_GPU_0, HGX_ERoT_CPU_0
        pub device_id: String,
        // Nonce used in attestation with both NRAS and BMC
        pub nonce: uuid::Uuid,
        // Device State.
        pub state: AttestationDeviceState,
        // State version will increase
        pub state_version: ConfigVersion,
        /// The result of the last attempt to change state
        pub state_outcome: Option<PersistentStateHandlerOutcome>,
        // Fetched latest value during attestation.
        pub metadata: Option<SpdmMachineDeviceMetadata>,
        // CA certificate link to fetch the certificate.
        pub ca_certificate_link: Option<String>,
        // CA certificate fetched from the link.
        pub ca_certificate: Option<CaCertificate>,
        // Evidence target link, used to trigger the measurement collection.
        pub evidence_target: Option<String>,
        // Collected Evidence.
        pub evidence: Option<Evidence>,
    }

    /// Major state, associated with Machine.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum AttestationState {
        // First state to check if attestation is supported or not.
        // If ComponentIntegrity field is None, indicates that attestation is not supported.
        CheckIfAttestationSupported,
        // Fetch all targets which supports attestation with following parameters:
        // "ComponentIntegrityEnabled": true,
        // "ComponentIntegrityType": "SPDM",
        // "ComponentIntegrityTypeVersion": "1.1.0",
        // If there is no device matching with above criteria, simply mark not-supported.
        // Delete all old targets and update with new list.
        // The list validation is taken care by SKU validation.
        FetchAttestationTargetsAndUpdateDb,
        // Fetch measurements, certificate and metadata
        FetchData,
        // Run verification with verifier
        Verification,
        // Apply appraisal policies
        ApplyEvidenceResultAppraisalPolicy,
        // All done
        Completed,
    }

    #[derive(Clone, Debug, thiserror::Error, PartialEq, Eq, Serialize, Deserialize)]
    pub enum SpdmHandlerError {
        #[error("Unable to complete measurement trigger: {0}")]
        TriggerMeasurementFail(String),
        #[error("Nras error: {0}")]
        NrasError(#[from] nras::NrasError),
        #[error("Missing values: {field} - {machine_id}/{device_id}")]
        MissingData {
            field: String,
            machine_id: MachineId,
            device_id: String,
        },
        #[error("Verifier not implemented at {module} for: {machine_id}/{device_id}")]
        VerifierNotImplemented {
            module: String,
            machine_id: MachineId,
            device_id: String,
        },
        #[error("Verification Failed: {0}")]
        VerificationFailed(String),
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum AttestationStatus {
        Success,
        NotSupported,
        Failure { cause: SpdmHandlerError },
    }

    pub enum DeviceType {
        Gpu,
        Cx7,
        Unknown,
    }

    impl FromStr for DeviceType {
        type Err = SpdmHandlerError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            Ok(if s.contains("GPU") {
                DeviceType::Gpu
            } else if s.contains("CX7") {
                DeviceType::Cx7
            } else {
                DeviceType::Unknown
            })
        }
    }

    /// Minor/sub-state, associated with device/component of a machine.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum FetchDataDeviceStates {
        // Each component may have a unique metadata structure.
        // but firmware-version is the most common and important metadata.
        FetchMetadata,
        // Certificate is needed for the attestation. The link is stored in ca_certificate_link
        // field.
        FetchCertificate,
        // Use Action URL to trigger the measurement collection.
        Trigger { retry_count: i32 },
        // Keep polling until measurement collection is completed.
        Poll { task_id: String, retry_count: i32 },
        // Collect using GET method.
        Collect,
        // Data is collected.
        // Sync state.
        Collected,
    }

    /// Minor/sub-state, associated with device/component of a machine.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum VerificationDeviceStates {
        GetVerifierResponse,
        VerifyResponse { state: nras::RawAttestationOutcome },
        // Sync state
        VerificationCompleted,
    }

    /// Minor/sub-state, associated with device/component of a machine.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum EvidenceResultAppraisalPolicyDeviceStates {
        ApplyAppraisalPolicy,
        // Sync State
        AppraisalPolicyValidationCompleted,
    }

    /// Minor/sub-state, associated with device/component of a machine.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum AttestationDeviceState {
        NotApplicable,
        FetchData(FetchDataDeviceStates),
        Verification(VerificationDeviceStates),
        ApplyEvidenceResultAppraisalPolicy(EvidenceResultAppraisalPolicyDeviceStates),
        // Final Sync State
        AttestationCompleted { status: AttestationStatus },
    }

    /// History table
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SpdmMachineStateSnapshot {
        pub machine_state: AttestationState,
        pub devices_state: HashMap<String, AttestationDeviceState>,
        pub device_state: Option<AttestationDeviceState>,
        pub machine_version: ConfigVersion,
        pub device_version: Option<ConfigVersion>,
        pub update_machine_version: bool,
        pub update_device_version: bool,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, FromRow)]
    pub struct SpdmObjectId_ {
        pub machine_id: MachineId,
        pub device_id: String,
    }

    #[derive(thiserror::Error, Debug, Clone)]
    pub enum SpdmObjectIdParseError {
        #[error("The Object ID must have 2 parts but not as should be {0:?}")]
        WrongFormat(String),
        #[error("The Machine ID parsing failed: {0}")]
        MachineIdParsingFailed(#[from] carbide_uuid::machine::MachineIdParseError),
    }

    #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, FromRow)]
    pub struct SpdmObjectId(pub MachineId, pub Option<String>);

    impl FromStr for SpdmObjectId {
        type Err = SpdmObjectIdParseError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let values = s.split(',').collect_vec();
            if values.len() != 2 {
                return Err(SpdmObjectIdParseError::WrongFormat(s.to_string()));
            }

            Ok(Self(
                values[0].parse().map_err(SpdmObjectIdParseError::from)?,
                if values[1].is_empty() {
                    None
                } else {
                    Some(values[1].to_string())
                },
            ))
        }
    }

    impl Display for SpdmObjectId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{},{}", self.0, self.1.clone().unwrap_or_default())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SpdmMachineAttestationHistory {
        pub machine_id: MachineId,
        pub updated_at: DateTime<Utc>,
        pub state_snapshot: SpdmMachineStateSnapshot,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SpdmMachineDeviceMetadata {
        pub firmware_version: Option<String>,
    }

    impl<'r> sqlx::FromRow<'r, PgRow> for SpdmMachineAttestationHistory {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let snapshot: sqlx::types::Json<SpdmMachineStateSnapshot> =
                row.try_get("state_snapshot")?;

            Ok(SpdmMachineAttestationHistory {
                machine_id: row.try_get("machine_id")?,
                updated_at: row.try_get("updated_at")?,
                state_snapshot: snapshot.0,
            })
        }
    }

    impl<'r> sqlx::FromRow<'r, PgRow> for SpdmMachineAttestation {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let controller_state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
                row.try_get("state_outcome")?;
            let controller_state: sqlx::types::Json<AttestationState> = row.try_get("state")?;

            Ok(SpdmMachineAttestation {
                machine_id: row.try_get("machine_id")?,
                requested_at: row.try_get("requested_at")?,
                started_at: row.try_get("started_at")?,
                canceled_at: row.try_get("canceled_at")?,
                state: controller_state.0,
                state_version: row.try_get("state_version")?,
                state_outcome: controller_state_outcome.map(|x| x.0),
                attestation_status: row.try_get("attestation_status")?,
            })
        }
    }

    impl<'r> sqlx::FromRow<'r, PgRow> for SpdmMachineDeviceAttestation {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let controller_state: sqlx::types::Json<AttestationDeviceState> =
                row.try_get("state")?;
            let ca_certificate: Option<sqlx::types::Json<CaCertificate>> =
                row.try_get("ca_certificate")?;
            let evidence: Option<sqlx::types::Json<Evidence>> = row.try_get("evidence")?;
            let metadata: Option<sqlx::types::Json<SpdmMachineDeviceMetadata>> =
                row.try_get("metadata")?;
            let controller_state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
                row.try_get("state_outcome")?;

            Ok(SpdmMachineDeviceAttestation {
                machine_id: row.try_get("machine_id")?,
                state: controller_state.0,
                state_version: row.try_get("state_version")?,
                state_outcome: controller_state_outcome.map(|x| x.0),
                device_id: row.try_get("device_id")?,
                nonce: row.try_get("nonce")?,
                metadata: metadata.map(|x| x.0),
                ca_certificate_link: row.try_get("ca_certificate_link")?,
                evidence_target: row.try_get("evidence_target")?,
                ca_certificate: ca_certificate.map(|x| x.0),
                evidence: evidence.map(|x| x.0),
            })
        }
    }

    impl<'r> sqlx::FromRow<'r, PgRow> for SpdmMachineSnapshot {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let machine: sqlx::types::Json<SpdmMachineAttestation> = row.try_get("machine")?;
            let device: Option<sqlx::types::Json<SpdmMachineDeviceAttestation>> =
                row.try_get("device")?;
            let bmc_info: sqlx::types::Json<BmcInfo> = row.try_get("bmc_info")?;
            let devices_state: sqlx::types::Json<HashMap<String, AttestationDeviceState>> =
                row.try_get("devices_state")?;

            Ok(SpdmMachineSnapshot {
                machine: machine.0,
                device: device.map(|x| x.0),
                devices_state: devices_state.0,
                bmc_info: bmc_info.0,
            })
        }
    }

    impl<'r> sqlx::FromRow<'r, PgRow> for SpdmMachineDetails {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let machine: sqlx::types::Json<SpdmMachineAttestation> = row.try_get("machine")?;
            let devices: sqlx::types::Json<Vec<SpdmMachineDeviceAttestation>> =
                row.try_get("devices")?;

            Ok(SpdmMachineDetails {
                machine: machine.0,
                devices: devices.0,
            })
        }
    }

    impl From<SpdmMachineDetails> for rpc::forge::attestation_response::AttestationMachineData {
        fn from(value: SpdmMachineDetails) -> Self {
            rpc::forge::attestation_response::AttestationMachineData {
                machine_id: Some(value.machine.machine_id),
                requested_at: Some(value.machine.requested_at.into()),
                started_at: value.machine.started_at.map(|x| x.into()),
                canceled_at: value.machine.canceled_at.map(|x| x.into()),
                state: format!("{:?}", value.machine.state),
                state_version: value.machine.state_version.to_string(),
                state_outcome: value.machine.state_outcome.map(|x| x.to_string()),
                status: format!("{:?}", value.machine.attestation_status),
                device_data: value.devices.iter().map(|x| x.clone().into()).collect_vec(),
            }
        }
    }

    impl From<SpdmMachineDeviceAttestation>
        for rpc::forge::attestation_response::AttestationDeviceData
    {
        fn from(value: SpdmMachineDeviceAttestation) -> Self {
            Self {
                device_id: value.device_id,
                nonce: Some(value.nonce.into()),
                state: format!("{:?}", value.state),
                metadata: value
                    .metadata
                    .as_ref()
                    .map(|x| serde_json::to_string(x).unwrap_or_default()),
            }
        }
    }

    impl From<SpdmMachineSnapshot> for SpdmMachineStateSnapshot {
        fn from(value: SpdmMachineSnapshot) -> Self {
            Self {
                machine_state: value.machine.state,
                devices_state: value.devices_state,
                device_state: value.device.clone().map(|x| x.state),
                machine_version: value.machine.state_version,
                device_version: value.device.map(|x| x.state_version),
                update_machine_version: false,
                update_device_version: false,
            }
        }
    }

    pub fn from_component_integrity(
        integrity: ComponentIntegrity,
        machine_id: MachineId,
    ) -> SpdmMachineDeviceAttestation {
        let ca_certificate_link = integrity
            .spdm
            .map(|x| x.identity_authentication)
            .map(|x| x.component_certificate)
            .map(|x| x.odata_id);

        let evidence_target =
            if let Some(Some(data)) = integrity.actions.map(|x| x.get_signed_measurements) {
                Some(data.target)
            } else {
                None
            };

        SpdmMachineDeviceAttestation {
            machine_id,
            device_id: integrity.id,
            nonce: uuid::Uuid::new_v4(),
            state: AttestationDeviceState::FetchData(FetchDataDeviceStates::FetchMetadata),
            state_version: ConfigVersion::initial(),
            state_outcome: None,
            metadata: None,
            ca_certificate_link,
            ca_certificate: None,
            evidence_target,
            evidence: None,
        }
    }

    #[async_trait::async_trait]
    pub trait Verifier: std::fmt::Debug + Send + Sync + 'static {
        fn client(&self, nras_config: nras::Config) -> Box<dyn nras::VerifierClient>;
        async fn parse_attestation_outcome(
            &self,
            nras_config: &nras::Config,
            state: &RawAttestationOutcome,
        ) -> Result<ProcessedAttestationOutcome, NrasError>;
    }

    #[derive(Debug, Default)]
    pub struct VerifierImpl {}

    #[async_trait::async_trait]
    impl Verifier for VerifierImpl {
        fn client(&self, nras_config: nras::Config) -> Box<dyn nras::VerifierClient> {
            Box::new(NrasVerifierClient::new_with_config(&nras_config))
        }
        async fn parse_attestation_outcome(
            &self,
            nras_config: &nras::Config,
            state: &RawAttestationOutcome,
        ) -> Result<ProcessedAttestationOutcome, NrasError> {
            // now create a KeyStore to validate those tokens
            let nras_keystore = nras::NrasKeyStore::new_with_config(nras_config).await?;
            let parser = nras::Parser::new_with_config(nras_config);
            parser.parse_attestation_outcome(state, &nras_keystore)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::attestation::spdm::SpdmObjectId;

    #[test]
    fn test_spdmobject_id_from_str() {
        let machine_id: MachineId = "fm100htv4fu8fpktl0e0qrg4dl58g2bc2g7naq0l6c15ruc22po1i5rfsq0"
            .parse()
            .unwrap();
        let device_id = "Device-1".to_string();
        let spdm_object_id = SpdmObjectId(machine_id, Some(device_id.clone()));

        let expected_str = format!("{},{}", machine_id, device_id);
        assert_eq!(expected_str, spdm_object_id.to_string());

        let parsed_object_id: SpdmObjectId = spdm_object_id.to_string().parse().unwrap();

        assert_eq!(parsed_object_id, spdm_object_id);
    }

    #[test]
    fn test_spdmobject_id_from_str_no_device() {
        let machine_id: MachineId = "fm100htv4fu8fpktl0e0qrg4dl58g2bc2g7naq0l6c15ruc22po1i5rfsq0"
            .parse()
            .unwrap();
        let spdm_object_id = SpdmObjectId(machine_id, None);

        let expected_str = format!("{},", machine_id);
        assert_eq!(expected_str, spdm_object_id.to_string());

        let parsed_object_id: SpdmObjectId = spdm_object_id.to_string().parse().unwrap();

        assert_eq!(parsed_object_id, spdm_object_id);
    }
}
