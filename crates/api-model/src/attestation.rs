/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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

    use config_version::ConfigVersion;
    use itertools::Itertools;
    use libredfish::model::component_integrity::{CaCertificate, Evidence};
    use rpc::forge::attestation_response::AttestationMachineData;
    use serde::{Deserialize, Serialize};
    use sqlx::Row;
    use sqlx::postgres::PgRow;

    use super::*;
    use crate::controller_outcome::PersistentStateHandlerOutcome;

    const _DB_LOCK_NAME: &str = "attestation_state_controller_lock";

    /// A SPDM machine and components snapshot.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SpdmMachineSnapshot {
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
        // when attestation is completed, this field will be updated with current value.
        pub last_known_metadata: Option<SpdmMachineDeviceMetadata>,
        // Fetched latest value during attestation.
        pub current_metadata: Option<SpdmMachineDeviceMetadata>,
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
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum AttestationStatus {
        Success,
        Failure { cause: String }, // TODO: Replace it with error type.
    }

    /// Minor/sub-state, associated with device/component of a machine.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum FetchMeasurementDeviceStates {
        // Each component may have a unique metadata structure.
        // but firmware-version is the most common and important metadata.
        FetchMetadata,
        // Certificate is needed for the attestation. The link is stored in ca_certificate_link
        // field.
        FetchCertificate,
        // Use Action URL to trigger the measurement collection.
        Trigger,
        // Keep polling until measurement collection is completed.
        Poll,
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
        VerifyResponse { state: SpdmVerifierResponse },
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
        FetchMesurements(FetchMeasurementDeviceStates),
        Verification(VerificationDeviceStates),
        ApplyEvidenceResultAppraisalPolicy(EvidenceResultAppraisalPolicyDeviceStates),
        AttestationCompleted { status: AttestationStatus },
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SpdmJwtEntry(pub String, pub String);

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SpdmVerifierResponse(pub SpdmJwtEntry, pub HashMap<String, String>);

    /// History table
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SpdmMachineHistoryState {
        pub state: AttestationState,
        pub devices_state: HashMap<String, AttestationDeviceState>,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SpdmMachineAttestationHistory {
        // Machine id. Host and DPU are treated at separate entity here.
        pub machine_id: MachineId,
        pub updated_at: DateTime<Utc>,
        pub state_snapshot: SpdmMachineHistoryState,
        pub state_version: ConfigVersion,
        pub attestation_status: SpdmAttestationStatus,
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SpdmMachineDeviceMetadata {
        pub firmware_version: Option<String>,
    }

    impl<'r> sqlx::FromRow<'r, PgRow> for SpdmMachineAttestationHistory {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let snapshot: sqlx::types::Json<SpdmMachineHistoryState> =
                row.try_get("state_snapshot")?;

            Ok(SpdmMachineAttestationHistory {
                machine_id: row.try_get("machine_id")?,
                updated_at: row.try_get("updated_at")?,
                state_snapshot: snapshot.0,
                state_version: row.try_get("state_version")?,
                attestation_status: row.try_get("attestation_status")?,
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
            let last_known_metadata: Option<sqlx::types::Json<SpdmMachineDeviceMetadata>> =
                row.try_get("last_known_metadata")?;
            let current_metadata: Option<sqlx::types::Json<SpdmMachineDeviceMetadata>> =
                row.try_get("current_metadata")?;

            Ok(SpdmMachineDeviceAttestation {
                machine_id: row.try_get("machine_id")?,
                state: controller_state.0,
                device_id: row.try_get("device_id")?,
                nonce: row.try_get("nonce")?,
                last_known_metadata: last_known_metadata.map(|x| x.0),
                current_metadata: current_metadata.map(|x| x.0),
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
            let devices: sqlx::types::Json<Vec<SpdmMachineDeviceAttestation>> =
                row.try_get("devices")?;

            Ok(SpdmMachineSnapshot {
                machine: machine.0,
                devices: devices.0,
            })
        }
    }

    impl From<SpdmMachineSnapshot> for AttestationMachineData {
        fn from(value: SpdmMachineSnapshot) -> Self {
            AttestationMachineData {
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
                last_known_metadata: value
                    .last_known_metadata
                    .as_ref()
                    .map(|x| serde_json::to_string(x).unwrap_or_default()),
                current_metadata: value
                    .current_metadata
                    .as_ref()
                    .map(|x| serde_json::to_string(x).unwrap_or_default()),
            }
        }
    }
}
