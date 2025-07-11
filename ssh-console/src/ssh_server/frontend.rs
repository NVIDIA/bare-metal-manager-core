/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::config::Config;
use crate::proxy_channel_message;
use crate::ssh_server::backend::BackendHandle;
use crate::ssh_server::backend_pool::BackendPool;
use eyre::Context;
use rpc::forge::ValidateTenantPublicKeyRequest;
use rpc::forge_api_client::ForgeApiClient;
use russh::keys::ssh_key::AuthorizedKeys;
use russh::keys::{Certificate, PublicKey, PublicKeyBase64};
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, MethodKind, MethodSet, Pty, Sig};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::Code;
use uuid::Uuid;

#[derive(Debug)]
pub struct Handler {
    pub config: Arc<Config>,
    pub forge_api_client: ForgeApiClient,

    backend_pool: Arc<BackendPool>,
    authenticated_user: RwLock<Option<Arc<String>>>,
    backends: RwLock<HashMap<ChannelId, Arc<BackendHandle>>>,
}

impl Handler {
    pub fn new(
        backend_pool: Arc<BackendPool>,
        config: Arc<Config>,
        forge_api_client: ForgeApiClient,
    ) -> Self {
        Self {
            config,
            forge_api_client,
            backend_pool,
            authenticated_user: Default::default(),
            backends: Default::default(),
        }
    }
}

impl russh::server::Handler for Handler {
    type Error = eyre::Error;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let Some(user) = self.authenticated_user.read().await.clone() else {
            return Err(eyre::format_err!(
                "BUG: channel_open_session called but we don't have an authenticated user"
            ));
        };

        // spawn the backend connection
        let channel_id = channel.id();
        let backend = self
            .backend_pool
            .ensure_connected(&user, &self.config, &self.forge_api_client)
            .await
            .with_context(|| format!("backend connection error for user {user}"))?;

        let mut to_frontend_rx = backend.subscribe();

        tokio::spawn(async move {
            while let Ok(msg) = to_frontend_rx.recv().await {
                match proxy_channel_message(msg.as_ref(), &channel).await {
                    Ok(()) => {}
                    Err(e) => {
                        tracing::error!("error sending message to frontend: {e:?}");
                        break;
                    }
                }
            }
            Ok::<(), eyre::Error>(())
        });

        // Save the backend writer in self.backends so the Handler methods can find it
        self.backends.write().await.insert(channel_id, backend);

        session
            .channel_success(channel_id)
            .context("error replying to channel_open_session")?;
        Ok(true)
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            // Note: openssh_certificate auth is just another kind of PublicKey auth, this should
            // imply either one.
            proceed_with_methods: Some(MethodSet::from([MethodKind::PublicKey].as_slice())),
            partial_success: false,
        })
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        let is_trusted =
            self.config
                .openssh_certificate_ca_fingerprints
                .iter()
                .any(|trusted_fingerprint| {
                    let client_ca_fingerprint = certificate
                        .signature_key()
                        .fingerprint(trusted_fingerprint.algorithm());
                    client_ca_fingerprint.eq(trusted_fingerprint)
                });

        if !is_trusted {
            tracing::warn!(
                user,
                "openssh certificate CA certificate not trusted, rejecting authentication"
            );
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        if !certificate_contains_role(certificate, &self.config.admin_certificate_role) {
            tracing::warn!(
                "certificate auth failed for user {user}, not in role {}",
                &self.config.admin_certificate_role
            );
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        tracing::info!(
            "certificate auth succeeded for user {user}, in role {}",
            &self.config.admin_certificate_role
        );
        self.authenticated_user
            .write()
            .await
            .replace(Arc::new(user.to_owned()));
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        // Authentication flow:
        // 1. If authorized_keys_path is set, check against file first
        // 2. If not found in file, validate via carbide-api
        // 3. If insecure mode is enabled, accept all connections

        let success = if pubkey_auth_admin_authorized_keys(public_key, &self.config, user)
            .context("error checking authorized_keys")?
        {
            true
        } else if Uuid::from_str(user).is_ok() {
            // Only try tenant auth if the user is a valid-looking UUID.
            pubkey_auth_tenant(user, public_key, &self.forge_api_client)
                .await
                .context("error validating pubkey with carbide-api")?
        } else {
            tracing::warn!(user, "rejecting public key for user {user}");
            false
        };

        let success = if !success && self.config.insecure {
            tracing::info!(
                "Overriding public-key rejection because we are in insecure (testing) mode"
            );
            true
        } else {
            success
        };

        if success {
            self.authenticated_user
                .write()
                .await
                .replace(Arc::new(user.to_owned()));
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                partial_success: false,
                proceed_with_methods: None,
            })
        }
    }

    /// Forward the data to the backend, but remove any escape sequences, to avoid letting the user
    /// drop to the BMC prompt.
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(backend) = self.backends.write().await.get_mut(&channel) {
            backend
                .to_backend_msg_tx
                .send(ChannelMsg::Data {
                    data: data.to_vec().into(),
                })
                .await
                .context("error writing data to channel")?;
        }
        Ok(())
    }

    /// Forward the data to the backend, but remove any escape sequences, to avoid letting the user
    /// drop to the BMC prompt.
    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(backend) = self.backends.write().await.get_mut(&channel) {
            backend
                .to_backend_msg_tx
                .send(ChannelMsg::ExtendedData {
                    data: data.to_vec().into(),
                    ext: code,
                })
                .await
                .context("error writing extended_data to channel")?;
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(backend) = self.backends.read().await.get(&channel) {
            // Ignore errors here
            backend.to_backend_msg_tx.send(ChannelMsg::Close).await.ok();
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(backend) = self.backends.read().await.get(&channel) {
            backend
                .to_backend_msg_tx
                .send(ChannelMsg::Eof)
                .await
                .context("error sending eof to backend")?;
        }
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(backend) = self.backends.read().await.get(&channel) {
            backend
                .to_backend_msg_tx
                .send(ChannelMsg::RequestPty {
                    want_reply: false,
                    term: term.to_string(),
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    terminal_modes: modes.to_vec(),
                })
                .await
                .context("error sending pty request to backend")?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(backend) = self.backends.read().await.get(&channel) {
            backend
                .to_backend_msg_tx
                .send(ChannelMsg::RequestShell { want_reply: false })
                .await
                .context("error sending shell request to backend")?;
        }
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(backend) = self.backends.read().await.get(&channel) {
            backend
                .to_backend_msg_tx
                .send(ChannelMsg::WindowChange {
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                })
                .await
                .context("error sending window change request to backend")?;
        }
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(backend) = self.backends.read().await.get(&channel) {
            backend
                .to_backend_msg_tx
                .send(ChannelMsg::Signal { signal })
                .await
                .context("error sending signal to backend")?;
        }
        Ok(())
    }

    // MARK: Unsupported ssh features

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::warn!(
            "Unsupported exec request: {}",
            String::from_utf8_lossy(data)
        );
        session.request_failure();
        session
            .data(channel, "Exec requests are unsupported\n".into())
            .ok();
        session.close(channel).ok();
        Ok(())
    }
}

/// Search for the given role in the Key ID field of a certificate, returning if it is declared.
fn certificate_contains_role(certificate: &Certificate, role: &str) -> bool {
    // Example:
    //     group=ngc user=ksimon roles=forge-dev-ssh-access,swngc-forge-admins,swngc-forge-corp-vault-admins,access-forge-dgxc-nonprod-admin,access-forge-dgxc-prod-admin
    let Some(roles_attr) = certificate
        .key_id()
        .split(' ')
        .find_map(|space_separated_chunk| {
            space_separated_chunk
                .split_once('=')
                .and_then(|(k, v)| if k == "roles" { Some(v) } else { None })
        })
    else {
        tracing::warn!(
            "Could not find `roles=` substring in key_id: {:?}",
            certificate.key_id()
        );
        return false;
    };

    roles_attr.split(',').any(|k| k == role)
}

/// Check if the user is in the configured authorized_keys file, which grants them admin access (can
/// log into any host.) This is generally only used for testing: In production we should be using
/// OpenSSH certificate auth, or no admin auth at all.
fn pubkey_auth_admin_authorized_keys(
    public_key: &PublicKey,
    config: &Config,
    user: &str,
) -> eyre::Result<bool> {
    let Some(authorized_keys_path) = config.authorized_keys_path.as_ref() else {
        return Ok(false);
    };

    let authorized_keys = AuthorizedKeys::read_file(authorized_keys_path).with_context(|| {
        format!(
            "Error reading authorized_keys file at {}",
            authorized_keys_path.display()
        )
    })?;

    if authorized_keys.iter().any(|entry| {
        entry
            .public_key()
            .public_key_base64()
            .eq(&public_key.public_key_base64())
    }) {
        tracing::info!(user, "accepting admin public key via authorized_keys");
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Authenticate the given pubkey via carbide-api, assuming the username is an instance ID.
async fn pubkey_auth_tenant(
    user: &str,
    public_key: &PublicKey,
    forge_api_client: &ForgeApiClient,
) -> eyre::Result<bool> {
    let authorized = match forge_api_client
        .validate_tenant_public_key(ValidateTenantPublicKeyRequest {
            instance_id: user.to_string(),
            tenant_public_key: public_key.public_key_base64(),
        })
        .await
    {
        // carbide-api has a weird way of just returning an internal error if the given pubkey is
        // not allowed to authenticate to this machine, rather than returning a valid-but-negative
        // response. So if it didn't fail, it's allowed. If it failed with an internal server error,
        // that's a rejection. If it failed for another reason, bubble up an error here (it will
        // still cause a reject.)
        Ok(_) => {
            tracing::info!(
                user,
                "accepting public key via carbide validate_tenant_public_key"
            );
            true
        }
        Err(e) => match e.code() {
            Code::Internal | Code::NotFound => {
                // Internal means the key doesn't match, NotFound means there's no instance like this
                tracing::warn!(
                    user,
                    "rejecting public key via carbide validate_tenant_public_key"
                );
                false
            }
            Code::InvalidArgument => {
                // InvalidArgument can happen if the user is not a valid instance ID.
                tracing::warn!(
                    "InvalidArgument when calling carbide-api to validate pubkey for {user}"
                );
                false
            }
            code => {
                // Any other error, we should just reject for safety.
                return Err(e).context(format!(
                    "Unexpected error calling carbide-api to validate pubkey for {user}: {code}"
                ));
            }
        },
    };

    Ok(authorized)
}
