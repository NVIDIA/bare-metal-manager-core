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

// these are not visible outside of this crate
mod client;
mod keystore;
mod parser;

// re-exports
use std::collections as stdcol;

pub use client::{NrasVerifierClient, VerifierClient};
pub use keystore::{KeyStore, NrasKeyStore};
pub use parser::Parser;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub nras_url: String,
    pub nras_gpu_url_suffix: String,
    pub nras_jwks_url: String,
    pub validate_jwt_expiry: bool,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            nras_url: Default::default(),
            nras_gpu_url_suffix: Default::default(),
            nras_jwks_url: Default::default(),
            validate_jwt_expiry: true,
        }
    }
}

#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq, Serialize, Deserialize)]
pub enum NrasError {
    #[error("Error talking to NRAS: {0}")]
    Communication(String),
    #[error("Error Serialising/Deserialising: {0}")]
    Serde(String),
    #[error("Error parsing verifier response: {0}")]
    ParsingVerifierResponse(String),
    #[error("Error - NotImplemented")]
    NotImplemented,
    #[error("Error parsing JWT token: {0}")]
    Jwt(String),
    #[error("Error looking up a decoding key: {0}")]
    DecodingKeyNotFound(String),
    #[error("Error forming JWK decoding key: {0}")]
    Jwk(String),
}

impl From<reqwest::Error> for NrasError {
    fn from(value: reqwest::Error) -> NrasError {
        NrasError::Communication(format!("Communication error: {}", value))
    }
}

type Evidence = String;
type DeviceCertificate = String;

#[derive(Serialize, Default)]
pub enum MachineArchitecture {
    #[serde(rename(serialize = "BLACKWELL"))]
    #[default]
    Blackwell,
}

#[derive(Serialize)]
pub struct EvidenceCertificate {
    pub evidence: Evidence,
    pub certificate: DeviceCertificate,
}

#[derive(Serialize, Default)]
pub struct DeviceAttestationInfo {
    #[serde(rename(serialize = "evidence_list"))]
    pub ec: Vec<EvidenceCertificate>,
    #[serde(rename(serialize = "arch"))]
    pub architecture: MachineArchitecture,
    pub nonce: String,
}

impl From<DeviceAttestationInfo> for String {
    fn from(value: DeviceAttestationInfo) -> String {
        serde_json::to_string(&value).unwrap()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawAttestationOutcome {
    // this typically corresponds to ["JWT", "<jwt_token>"] entry in the response
    pub overall_outcome: (String, String),
    // this typically corresponds to {"GPU-0": "<jwt_token>"} entries
    pub devices_outcome: stdcol::HashMap<String, String>,
}

#[derive(Debug)]
pub struct ProcessedAttestationOutcome {
    pub attestation_passed: bool,
    // the key is submod name, e.g. "GPU-0", the value are the claims
    // extracted from that submod
    pub devices: stdcol::HashMap<String, stdcol::HashMap<String, String>>,
}
