/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::io::Read;

use eyre::WrapErr;
use rpc::forge::{CredentialCreationRequest, CredentialDeletionRequest, CredentialType};

use super::args::{DeleteArgs, SetArgs};
use crate::errors::{CarbideCliError, CarbideCliResult};
use crate::rpc::ApiClient;

fn read_token(args: &SetArgs) -> CarbideCliResult<String> {
    let token = if args.token_file.as_os_str() == "-" {
        let mut token = String::new();
        std::io::stdin()
            .read_to_string(&mut token)
            .wrap_err("failed to read firmware artifact access token from standard input")?;

        token
    } else {
        std::fs::read_to_string(&args.token_file).wrap_err_with(|| {
            format!(
                "failed to read firmware artifact access token from {}",
                args.token_file.display()
            )
        })?
    };

    // Artifact tokens are opaque. Preserve valid UTF-8 content exactly as supplied,
    // including whitespace and line endings.
    if token.is_empty() {
        return Err(CarbideCliError::GenericError(
            "firmware artifact access token must not be empty".to_string(),
        ));
    }

    Ok(token)
}

pub(super) async fn set(args: SetArgs, api_client: &ApiClient) -> CarbideCliResult<()> {
    let token = read_token(&args)?;
    api_client
        .0
        .create_credential(CredentialCreationRequest {
            credential_type: CredentialType::FirmwareArtifactAccessToken.into(),
            username: None,
            password: token,
            vendor: None,
            mac_address: None,
            credential_name: Some(args.name),
        })
        .await?;

    Ok(())
}

pub(super) async fn delete(args: DeleteArgs, api_client: &ApiClient) -> CarbideCliResult<()> {
    api_client
        .0
        .delete_credential(CredentialDeletionRequest {
            credential_type: CredentialType::FirmwareArtifactAccessToken.into(),
            username: None,
            mac_address: None,
            credential_name: Some(args.name),
        })
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn token_file_contents_are_preserved() {
        let path = std::env::temp_dir().join(format!("nico-firmware-token-{}", std::process::id()));
        fs::write(&path, " token value \r\n").expect("write token fixture");

        let args = SetArgs {
            name: "repository-a".to_string(),
            token_file: path.clone(),
        };

        let token = read_token(&args).expect("read token");
        fs::remove_file(path).expect("remove token fixture");

        assert_eq!(token, " token value \r\n");
    }

    #[test]
    fn token_file_error_identifies_the_requested_path() {
        let path = std::env::temp_dir()
            .join(format!(
                "nico-firmware-token-missing-{}",
                std::process::id()
            ))
            .join("token");

        let args = SetArgs {
            name: "repository-a".to_string(),
            token_file: path.clone(),
        };

        let error = read_token(&args).expect_err("missing token file must fail");

        assert_eq!(
            error.to_string(),
            format!(
                "failed to read firmware artifact access token from {}",
                path.display()
            )
        );

        let CarbideCliError::EyreReport(report) = error else {
            panic!("expected an EyreReport");
        };

        let io_error = report
            .downcast_ref::<std::io::Error>()
            .expect("I/O source should remain in the error chain");

        assert_eq!(io_error.kind(), std::io::ErrorKind::NotFound);
    }
}
