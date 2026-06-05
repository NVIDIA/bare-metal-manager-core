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

//! TPM related operations

use std::process::Command;

use x509_parser::prelude::{FromDer, X509Certificate};

const TPM2_GET_EK_CERTIFICATE: &str = "tpm2_getekcertificate";
const TPM2_NV_READ: &str = "tpm2_nvread";
const TPM_EK_CERT_NV_INDICES: &[&str] = &[
    "0x01c00002", // RSA EK cert
    "0x01c00012", // RSA 2048 EK cert
    "0x01c0000a", // ECC EK cert
    "0x01c00014", // ECC NIST P-256 EK cert
    "0x01c0001c", // RSA 3072 EK cert
    "0x01c0001e", // RSA 4096 EK cert
    "0x01c00016", // ECC NIST P-384 EK cert
    "0x01c00018", // ECC NIST P-521 EK cert
    "0x01c0001a", // ECC SM2 P-256 EK cert
];

/// Enumerates errors for TPM related operations
#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("Unable to invoke subprocess {0}: {1}")]
    Subprocess(&'static str, std::io::Error),
    #[error("Subprocess exited with exit code {0:?}. Stderr: {1}")]
    SubprocessStatusNotOk(Option<i32>, String),
    #[error("TPM EK certificate bytes from {0} were not parseable as DER X.509")]
    InvalidEkCertificate(&'static str),
    #[error("Unable to read TPM EK certificate: {primary_error}; NV fallback errors: {nv_errors}")]
    EkCertificateNotFound {
        primary_error: Box<TpmError>,
        nv_errors: String,
    },
}

/// Returns the TPM's endorsement key certificate in binary format
pub fn get_ek_certificate() -> Result<Vec<u8>, TpmError> {
    get_ek_certificate_with_runner(&StdCommandRunner)
}

pub fn is_tpm_present() -> bool {
    std::path::Path::new("/dev/tpmrm0").exists() || std::path::Path::new("/dev/tpm0").exists()
}

#[derive(Debug)]
struct CommandOutput {
    status_success: bool,
    status_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

trait CommandRunner {
    fn output(&self, program: &'static str, args: &[&str])
    -> Result<CommandOutput, std::io::Error>;
}

struct StdCommandRunner;

impl CommandRunner for StdCommandRunner {
    fn output(
        &self,
        program: &'static str,
        args: &[&str],
    ) -> Result<CommandOutput, std::io::Error> {
        let output = Command::new(program).args(args).output()?;

        Ok(CommandOutput {
            status_success: output.status.success(),
            status_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

fn get_ek_certificate_with_runner(runner: &impl CommandRunner) -> Result<Vec<u8>, TpmError> {
    match get_ek_certificate_from_tool(runner) {
        Ok(cert) => Ok(cert),
        Err(primary_error) => {
            tracing::warn!(
                "Could not read TPM EK certificate using {TPM2_GET_EK_CERTIFICATE}: {primary_error:?}; probing known NV indices"
            );
            let mut certs = vec![];
            let mut nv_errors = vec![];
            for index in TPM_EK_CERT_NV_INDICES {
                match get_ek_certificate_from_nv_index(runner, index) {
                    Ok(cert) => {
                        tracing::info!("Read TPM EK certificate from NV index {index}");
                        certs.extend_from_slice(&cert);
                    }
                    Err(e) => nv_errors.push(format!("{index}: {e}")),
                }
            }

            if !certs.is_empty() {
                return Ok(certs);
            }

            Err(TpmError::EkCertificateNotFound {
                primary_error: Box::new(primary_error),
                nv_errors: nv_errors.join("; "),
            })
        }
    }
}

fn get_ek_certificate_from_tool(runner: &impl CommandRunner) -> Result<Vec<u8>, TpmError> {
    // TODO: Do we need the `--raw` or `--offline` parameters?
    let output = runner
        .output(TPM2_GET_EK_CERTIFICATE, &[])
        .map_err(|e| TpmError::Subprocess(TPM2_GET_EK_CERTIFICATE, e))?;

    cert_from_output(TPM2_GET_EK_CERTIFICATE, output)
}

fn get_ek_certificate_from_nv_index(
    runner: &impl CommandRunner,
    index: &str,
) -> Result<Vec<u8>, TpmError> {
    let output = runner
        .output(TPM2_NV_READ, &["-C", "o", index])
        .map_err(|e| TpmError::Subprocess(TPM2_NV_READ, e))?;

    cert_from_nv_output(TPM2_NV_READ, output)
}

fn cert_from_output(source: &'static str, output: CommandOutput) -> Result<Vec<u8>, TpmError> {
    let stdout = checked_stdout(output)?;

    X509Certificate::from_der(&stdout).map_err(|_| TpmError::InvalidEkCertificate(source))?;

    Ok(stdout)
}

fn cert_from_nv_output(source: &'static str, output: CommandOutput) -> Result<Vec<u8>, TpmError> {
    let stdout = checked_stdout(output)?;
    let (remaining, _) =
        X509Certificate::from_der(&stdout).map_err(|_| TpmError::InvalidEkCertificate(source))?;
    let cert_len = stdout.len() - remaining.len();

    Ok(stdout[..cert_len].to_vec())
}

fn checked_stdout(output: CommandOutput) -> Result<Vec<u8>, TpmError> {
    if !output.status_success {
        let err = String::from_utf8(output.stderr).unwrap_or_else(|_| "Invalid UTF8".to_string());
        return Err(TpmError::SubprocessStatusNotOk(output.status_code, err));
    }

    Ok(output.stdout)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;

    use rcgen::{CertifiedKey, generate_simple_self_signed};

    use super::*;

    #[derive(Debug)]
    struct FakeCall {
        program: &'static str,
        args: Vec<&'static str>,
        result: Result<CommandOutput, io::Error>,
    }

    #[derive(Debug)]
    struct FakeRunner {
        calls: std::cell::RefCell<VecDeque<FakeCall>>,
    }

    impl FakeRunner {
        fn new(calls: Vec<FakeCall>) -> Self {
            Self {
                calls: std::cell::RefCell::new(calls.into()),
            }
        }
    }

    impl CommandRunner for FakeRunner {
        fn output(
            &self,
            program: &'static str,
            args: &[&str],
        ) -> Result<CommandOutput, std::io::Error> {
            let call = self
                .calls
                .borrow_mut()
                .pop_front()
                .expect("unexpected call");
            assert_eq!(call.program, program);
            assert_eq!(call.args, args);
            call.result
        }
    }

    fn test_ek_cert_der(common_name: &str) -> Vec<u8> {
        let CertifiedKey { cert, .. } =
            generate_simple_self_signed(vec![common_name.to_string()]).unwrap();
        cert.der().to_vec()
    }

    fn successful_output(stdout: &[u8]) -> CommandOutput {
        CommandOutput {
            status_success: true,
            status_code: Some(0),
            stdout: stdout.to_vec(),
            stderr: vec![],
        }
    }

    fn failed_output(stderr: &str) -> CommandOutput {
        CommandOutput {
            status_success: false,
            status_code: Some(2),
            stdout: vec![],
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn cert_with_trailing_nv_bytes(cert: &[u8]) -> Vec<u8> {
        let mut stdout = cert.to_vec();
        stdout.extend_from_slice(b"unspecified NV bytes");
        stdout
    }

    fn primary_tool_failed_call() -> FakeCall {
        FakeCall {
            program: TPM2_GET_EK_CERTIFICATE,
            args: vec![],
            result: Ok(failed_output(
                "ERROR: Must specify the EK public key path\n",
            )),
        }
    }

    fn nv_read_call(index: &'static str, result: Result<CommandOutput, io::Error>) -> FakeCall {
        FakeCall {
            program: TPM2_NV_READ,
            args: vec!["-C", "o", index],
            result,
        }
    }

    fn failed_nv_read_call(index: &'static str) -> FakeCall {
        nv_read_call(index, Ok(failed_output("NV index not available")))
    }

    #[test]
    fn get_ek_certificate_returns_primary_tool_certificate() {
        let test_ek_cert_der = test_ek_cert_der("primary");
        let runner = FakeRunner::new(vec![FakeCall {
            program: TPM2_GET_EK_CERTIFICATE,
            args: vec![],
            result: Ok(successful_output(&test_ek_cert_der)),
        }]);

        assert_eq!(
            get_ek_certificate_with_runner(&runner).unwrap(),
            test_ek_cert_der
        );
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn get_ek_certificate_falls_back_to_nv_indices() {
        let test_ek_cert_der = test_ek_cert_der("fallback");
        let nv_stdout = cert_with_trailing_nv_bytes(&test_ek_cert_der);
        let mut calls = vec![
            primary_tool_failed_call(),
            nv_read_call(TPM_EK_CERT_NV_INDICES[0], Ok(successful_output(&nv_stdout))),
        ];
        calls.extend(
            TPM_EK_CERT_NV_INDICES[1..]
                .iter()
                .map(|&index| failed_nv_read_call(index)),
        );
        let runner = FakeRunner::new(calls);

        assert_eq!(
            get_ek_certificate_with_runner(&runner).unwrap(),
            test_ek_cert_der
        );
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn get_ek_certificate_skips_invalid_nv_data() {
        let test_ek_cert_der = test_ek_cert_der("valid");
        let mut calls = vec![
            primary_tool_failed_call(),
            nv_read_call(
                TPM_EK_CERT_NV_INDICES[0],
                Ok(successful_output(b"not a certificate")),
            ),
            nv_read_call(
                TPM_EK_CERT_NV_INDICES[1],
                Ok(successful_output(&test_ek_cert_der)),
            ),
        ];
        calls.extend(
            TPM_EK_CERT_NV_INDICES[2..]
                .iter()
                .map(|&index| failed_nv_read_call(index)),
        );
        let runner = FakeRunner::new(calls);

        assert_eq!(
            get_ek_certificate_with_runner(&runner).unwrap(),
            test_ek_cert_der
        );
        assert!(runner.calls.borrow().is_empty());
    }

    #[test]
    fn get_ek_certificate_concatenates_multiple_nv_certs_in_tool_order() {
        let first_cert = test_ek_cert_der("first");
        let second_cert = test_ek_cert_der("second");
        let first_nv_stdout = cert_with_trailing_nv_bytes(&first_cert);
        let second_nv_stdout = cert_with_trailing_nv_bytes(&second_cert);
        let mut calls = vec![
            primary_tool_failed_call(),
            nv_read_call(
                TPM_EK_CERT_NV_INDICES[0],
                Ok(successful_output(&first_nv_stdout)),
            ),
            nv_read_call(
                TPM_EK_CERT_NV_INDICES[1],
                Ok(successful_output(&second_nv_stdout)),
            ),
        ];
        calls.extend(
            TPM_EK_CERT_NV_INDICES[2..]
                .iter()
                .map(|&index| failed_nv_read_call(index)),
        );
        let runner = FakeRunner::new(calls);

        let mut expected = first_cert;
        expected.extend_from_slice(&second_cert);

        assert_eq!(get_ek_certificate_with_runner(&runner).unwrap(), expected);
        assert!(runner.calls.borrow().is_empty());
    }
}
