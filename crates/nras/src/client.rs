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

use std::collections as stdcol;

use async_trait::async_trait;
use serde_json as sj;

use crate::{DeviceAttestationInfo, NrasError, RawAttestationOutcome};

// trait to invoke REST methods on the NRAS service
#[async_trait]
pub trait VerifierClient: std::fmt::Debug + Send + Sync + 'static {
    async fn attest_gpu(
        &self,
        device_attestation_info: &DeviceAttestationInfo,
    ) -> Result<RawAttestationOutcome, NrasError>;
    async fn attest_dpu(
        &self,
        device_attestation_info: &DeviceAttestationInfo,
    ) -> Result<RawAttestationOutcome, NrasError>;
    async fn attest_cx7(
        &self,
        device_attestation_info: &DeviceAttestationInfo,
    ) -> Result<RawAttestationOutcome, NrasError>;
}

#[derive(Debug)]
pub struct NrasVerifierClient {
    config: crate::Config,
    http_client: reqwest::Client,
}

// TODO: add config which would allow configuring the URL paths for gpu, dpu, cx7
impl NrasVerifierClient {
    pub fn new_with_config(config: &crate::Config) -> NrasVerifierClient {
        NrasVerifierClient {
            config: config.clone(),
            http_client: reqwest::Client::new(),
        }
    }
}

// implementation of the trait for the NRAS service
#[async_trait]
impl VerifierClient for NrasVerifierClient {
    async fn attest_gpu(
        &self,
        device_attestation_info: &DeviceAttestationInfo,
    ) -> Result<RawAttestationOutcome, NrasError> {
        // prepare the request
        // submit to NRAS

        let att_response = self
            .http_client
            .post(format!(
                "{}{}",
                self.config.nras_url, self.config.nras_gpu_url_suffix
            ))
            .header("Content-Type", "application/json")
            .body(serde_json::to_string(device_attestation_info).map_err(|e| {
                NrasError::Serde(format!("Error Serializing Attestation Request: {}", e))
            })?)
            .send()
            .await?;

        let status_code = att_response.status();
        let response_text = att_response.text().await?;

        if status_code != reqwest::StatusCode::OK {
            return Err(NrasError::Communication(format!(
                "NRAS returned status code {} and message {}",
                status_code, response_text
            )));
        }

        // read the response and map to the RawAttestationOutcome
        let verifier_response: RawAttestationOutcome =
            serde_json::from_str::<serde_json::Value>(&response_text)
                .map_err(|e| {
                    NrasError::Serde(format!(
                        "Error mapping Verifier Response to serde Value: {}",
                        e
                    ))
                })?
                .try_into()?;

        Ok(verifier_response)
    }

    async fn attest_dpu(
        &self,
        _device_attestation_info: &DeviceAttestationInfo,
    ) -> Result<RawAttestationOutcome, NrasError> {
        Err(NrasError::NotImplemented)
    }
    async fn attest_cx7(
        &self,
        _device_attestation_info: &DeviceAttestationInfo,
    ) -> Result<RawAttestationOutcome, NrasError> {
        Err(NrasError::NotImplemented)
    }
}

/*
* The incoming value has the following format:
[
  ["JWT", "jwt_token"],       // Element 0: Platform-level statements which is JWT in this case
  {"GPU-0" : "jwt_token"},    // Element 1: Per-GPU statements // GPU-0
  {"GPU-1" : "jwt_token"}     // Element 2: Per-GPU statements // GPU-1
  etc
]
* Any validation mismatch is treated as an error, and the deserialization is aborted altogether.
*/
impl TryFrom<serde_json::Value> for RawAttestationOutcome {
    type Error = NrasError;

    fn try_from(value: serde_json::Value) -> Result<RawAttestationOutcome, NrasError> {
        // parse the value
        let mut overall_outcome = (String::new(), String::new());
        let mut devices_outcome = stdcol::HashMap::<String, String>::new();
        match value {
            serde_json::Value::Array(elems) => {
                // iterate over elements and populate the hash map
                for elem in elems {
                    match elem {
                        serde_json::Value::Object(map) => {
                            let (key, value) = extract_map_obj(&map)?;
                            devices_outcome.insert(key.clone(), value.clone());
                        }
                        serde_json::Value::Array(arr_values) => {
                            let (key, value) = extract_array_obj(&arr_values)?;
                            overall_outcome = (key.clone(), value.clone());
                        }
                        _ => {
                            return Err(NrasError::ParsingVerifierResponse(
                                "Verifier Response contains not an object not an array".to_string(),
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(NrasError::ParsingVerifierResponse(
                    "The incoming JSON object is not an array".to_string(),
                ));
            }
        }

        Ok(RawAttestationOutcome {
            overall_outcome,
            devices_outcome,
        })
    }
}

fn is_valid_jwt(jwt: &str) -> bool {
    jsonwebtoken::dangerous::insecure_decode::<sj::Value>(jwt).is_ok()
}

fn extract_map_obj(
    map: &serde_json::Map<String, serde_json::Value>,
) -> Result<(String, String), NrasError> {
    // do some validation beforehand
    if map.is_empty() {
        return Err(NrasError::ParsingVerifierResponse(
            "JSON Object for element is empty".to_string(),
        ));
    }
    if map.len() > 1 {
        return Err(NrasError::ParsingVerifierResponse(
            "JSON Object for element has more than one entry".to_string(),
        ));
    }
    // this should never happen because of the above checks, but still ...
    let Some(entry) = map.iter().next() else {
        return Err(NrasError::ParsingVerifierResponse(
            "Internal Error: Empty JSON Object".to_string(),
        ));
    };

    let key = entry.0;
    let value = match entry.1 {
        serde_json::Value::String(s) => s,
        _ => {
            return Err(NrasError::ParsingVerifierResponse(
                "JSON Object for element is empty".to_string(),
            ));
        }
    };

    Ok((key.clone(), value.clone()))
}

fn extract_array_obj(arr_values: &Vec<serde_json::Value>) -> Result<(String, String), NrasError> {
    // find an element named "JWT", and a JWT element
    let mut jwt_found = false;
    let mut jwt_value = String::new();

    for arr_value in arr_values {
        match arr_value {
            serde_json::Value::String(s) => {
                if s == "JWT" {
                    jwt_found = true;
                } else {
                    // try and partially parse the jwt token
                    if is_valid_jwt(s) {
                        jwt_value = s.clone();
                    } else {
                        return Err(NrasError::ParsingVerifierResponse(
                            "Not a JWT token in an array".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(NrasError::ParsingVerifierResponse(
                    "JSON Array contains non string value".to_string(),
                ));
            }
        }
    }

    if jwt_found && !jwt_value.is_empty() {
        Ok(("JWT".to_string(), jwt_value))
    } else {
        Err(NrasError::ParsingVerifierResponse(
            "JSON Array does not contain JWT element".to_string(),
        ))
    }
}
