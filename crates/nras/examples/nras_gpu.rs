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
use nras::VerifierClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = nras::Config {
        nras_url: "https://nras.attestation-dev.nvidia.com".to_string(),
        nras_gpu_url_suffix: "/v4/attest/gpu/health".to_string(),
        nras_jwks_url: "https://nras.attestation-dev.nvidia.com/.well-known/jwks.json".to_string(),
        ..Default::default()
    };

    // create nras client
    let nras_verifier_client = nras::NrasVerifierClient::new_with_config(&config);

    // and obtain raw attestation - contains just JWT tokens
    let verifier_response = nras_verifier_client
        .attest_gpu(&nras::DeviceAttestationInfo {
            nonce: "abcdef13455".to_string(),
            architecture: nras::MachineArchitecture::Blackwell,
            ec: vec![nras::EvidenceCertificate {
                evidence: "abdetg2345".to_string(),
                certificate: "abcderg8576".to_string(),
            }],
        })
        .await?;

    println!("RawAttestationOutcome is: {:#?}", verifier_response);

    // now create a KeyStore to validate those tokens
    let nras_keystore = nras::NrasKeyStore::new_with_config(&config).await?;

    let parser = nras::Parser::new_with_config(&config);

    let processed_response =
        parser.parse_attestation_outcome(&verifier_response, &nras_keystore)?;

    println!("ProcessedAttestationOutcome is: {:#?}", processed_response);

    Ok(())
}
