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
    use std::fmt::Display;
    use std::str::FromStr;

    use config_version::ConfigVersion;
    use itertools::Itertools;
    use libredfish::model::component_integrity::{CaCertificate, Evidence};
    use nras::{NrasError, NrasVerifierClient, ProcessedAttestationOutcome, RawAttestationOutcome};
    use serde::{Deserialize, Serialize};
    use sqlx::Row;
    use sqlx::postgres::PgRow;

    use super::*;
    use crate::bmc_info::BmcInfo;
    use crate::controller_outcome::PersistentStateHandlerOutcome;

    /// Data model to store progress of attestation related to a device/component of a machine BMC (e.g.
    /// GPU, CPU, BMC, CX7)
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct SpdmDeviceAttestation {
        // Host or DPU's machine id
        pub machine_id: MachineId,
        // Component/device of the machine (GPU, CPU, BMC)
        // e.g. HGX_IRoT_GPU_0, HGX_ERoT_CPU_0
        pub device_id: String,
        // BMC info to create a redfish client
        pub bmc_info: BmcInfo,
        // Nonce used in attestation with both NRAS and BMC
        pub nonce: uuid::Uuid,
        // Device State.
        pub state: SpdmAttestationState,
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
        // timestamps
        pub started_at: DateTime<Utc>,
        pub cancelled_at: Option<DateTime<Utc>>,
        pub completed_at: Option<DateTime<Utc>>,
    }

    /// Major state, associated with Machine.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub enum SpdmAttestationState {
        FetchMetadata,
        FetchCertificate,
        TriggerEvidenceCollection { retry_count: i32 },
        PollEvidenceCollection { task_id: String, retry_count: i32 },
        NrasVerification,
        ApplyAppraisalPolicy,
        Passed,
        Failed(String),
        Cancelled,
    }

    impl<'r> sqlx::FromRow<'r, PgRow> for SpdmAttestationState {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let controller_state: sqlx::types::Json<SpdmAttestationState> = row.try_get("state")?;
            Ok(controller_state.0)
        }
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

    #[derive(Debug)]
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
    pub struct SpdmObjectId(pub MachineId, pub String);

    impl FromStr for SpdmObjectId {
        type Err = SpdmObjectIdParseError;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let values = s.split(',').collect_vec();
            if values.len() != 2 {
                return Err(SpdmObjectIdParseError::WrongFormat(s.to_string()));
            }

            Ok(Self(
                values[0].parse().map_err(SpdmObjectIdParseError::from)?,
                values[1].to_string(),
            ))
        }
    }

    impl Display for SpdmObjectId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{},{}", self.0, self.1.clone())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    pub struct SpdmMachineDeviceMetadata {
        pub firmware_version: Option<String>,
    }

    impl<'r> sqlx::FromRow<'r, PgRow> for SpdmDeviceAttestation {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let controller_state: sqlx::types::Json<SpdmAttestationState> = row.try_get("state")?;
            let bmc_info: sqlx::types::Json<BmcInfo> = row.try_get("bmc_info")?;

            let ca_certificate: Option<sqlx::types::Json<CaCertificate>> =
                row.try_get("ca_certificate")?;
            let evidence: Option<sqlx::types::Json<Evidence>> = row.try_get("evidence")?;
            let metadata: Option<sqlx::types::Json<SpdmMachineDeviceMetadata>> =
                row.try_get("metadata")?;
            let controller_state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
                row.try_get("state_outcome")?;

            Ok(SpdmDeviceAttestation {
                machine_id: row.try_get("machine_id")?,
                state: controller_state.0,
                state_version: row.try_get("state_version")?,
                state_outcome: controller_state_outcome.map(|x| x.0),
                device_id: row.try_get("device_id")?,
                nonce: row.try_get("nonce")?,
                bmc_info: bmc_info.0,
                metadata: metadata.map(|x| x.0),
                ca_certificate_link: row.try_get("ca_certificate_link")?,
                evidence_target: row.try_get("evidence_target")?,
                ca_certificate: ca_certificate.map(|x| x.0),
                evidence: evidence.map(|x| x.0),
                started_at: row.try_get("started_at")?,
                cancelled_at: row.try_get("cancelled_at")?,
                completed_at: row.try_get("completed_at")?,
            })
        }
    }

    #[derive(FromRow, Debug, Clone)]
    pub struct SpdmDeviceAttestationDetails {
        pub machine_id: MachineId,
        pub device_id: String,
        pub state: SpdmAttestationState,
        // timestamps
        pub started_at: DateTime<Utc>,
        pub cancelled_at: Option<DateTime<Utc>>,
        pub completed_at: Option<DateTime<Utc>>,
    }

    impl SpdmDeviceAttestationDetails {
        pub fn get_failure_cause(&self) -> Option<String> {
            if let SpdmAttestationState::Failed(msg) = &self.state {
                Some(format!(
                    "Device: {}, failed reason: {}",
                    self.device_id, msg
                ))
            } else {
                None
            }
        }
    }

    impl<'r> sqlx::FromRow<'r, PgRow> for SpdmDeviceAttestationDetails {
        fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
            let controller_state: sqlx::types::Json<SpdmAttestationState> = row.try_get("state")?;

            Ok(SpdmDeviceAttestationDetails {
                machine_id: row.try_get("machine_id")?,
                state: controller_state.0,
                device_id: row.try_get("device_id")?,
                started_at: row.try_get("started_at")?,
                cancelled_at: row.try_get("cancelled_at")?,
                completed_at: row.try_get("completed_at")?,
            })
        }
    }

    impl From<SpdmDeviceAttestationDetails> for rpc::forge::SpdmAttestationDetails {
        fn from(value: SpdmDeviceAttestationDetails) -> Self {
            rpc::forge::SpdmAttestationDetails {
                machine_id: Some(value.machine_id),
                completed_at: value.completed_at.map(|x| x.into()),
                started_at: Some(value.started_at.into()),
                cancelled_at: value.cancelled_at.map(|x| x.into()),
                state: format!("{:?}", value.state),
                device_id: value.device_id,
            }
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
        let spdm_object_id = SpdmObjectId(machine_id, device_id.clone());

        let expected_str = format!("{},{}", machine_id, device_id);
        assert_eq!(expected_str, spdm_object_id.to_string());

        let parsed_object_id: SpdmObjectId = spdm_object_id.to_string().parse().unwrap();

        assert_eq!(parsed_object_id, spdm_object_id);
    }
}
