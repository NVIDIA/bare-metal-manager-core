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
use crate::bmc::client::BmcConnectionSubscription;
use crate::bmc::client_pool::BmcConnectionStore;
use crate::bmc::connection::Kind;
use crate::bmc::message_proxy;
use crate::bmc::message_proxy::{ChannelMsgOrExec, ExecReply};
use crate::config::Config;
use crate::shutdown_handle::ShutdownHandle;
use crate::ssh_server::ServerMetrics;
use eyre::Context;
use lazy_static::lazy_static;
use rpc::forge::ValidateTenantPublicKeyRequest;
use rpc::forge_api_client::ForgeApiClient;
use russh::keys::ssh_key::AuthorizedKeys;
use russh::keys::{Certificate, PublicKey, PublicKeyBase64};
use russh::server::{Auth, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg, MethodKind, MethodSet, Pty};
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tonic::Code;
use uuid::Uuid;

static EXEC_TIMEOUT: Duration = Duration::from_secs(10);

static BANNER_SSH_BMC: &str = "\
+------------------------------------------------------------------------------+\r\n\
|                 NVIDIA Forge SSH Serial Console (beta)                       |\r\n\
+------------------------------------------------------------------------------+\r\n\
|             Use SSH escape sequences to manage this session.                 |\r\n\
|      (Note that escapes are only recognized immediately after newline.)      |\r\n\
|                               ~. | terminate session                         |\r\n\
|                               ~? | Help                                      |\r\n\
+------------------------------------------------------------------------------+\r\n\
";

static BANNER_IPMI_BMC: &str = "\
+------------------------------------------------------------------------------+\r\n\
|                 NVIDIA Forge SSH Serial Console (beta)                       |\r\n\
+------------------------------------------------------------------------------+\r\n\
|             Use SSH escape sequences to manage this session.                 |\r\n\
|      (Note that escapes are only recognized immediately after newline.)      |\r\n\
|                               ~. | terminate session                         |\r\n\
|                               ~? | Help                                      |\r\n\
|   This system supports power reset requests. To reboot this system, append   |\r\n\
|                \"power reset\" to your original SSH command                    |\r\n\
|                (e.g. ssh <host>@<console-ip> power reset)                    |\r\n\
+------------------------------------------------------------------------------+\r\n\
";

lazy_static! {
    static ref CERT_AUTH_FAILURE_METRIC: [opentelemetry::KeyValue; 1] =
        [opentelemetry::KeyValue::new(
            "auth_type",
            "openssh_certificate",
        )];
    static ref PUBKEY_AUTH_FAILURE_METRIC: [opentelemetry::KeyValue; 1] =
        [opentelemetry::KeyValue::new("auth_type", "public_key",)];
}

pub struct Handler {
    config: Arc<Config>,
    forge_api_client: ForgeApiClient,
    bmc_connection_store: BmcConnectionStore,
    authenticated_user: Option<String>,
    per_client_state: HashMap<ChannelId, PerClientState>,
    metrics: Arc<ServerMetrics>,
    last_auth_failure: Option<AuthFailureReason>,
    // Specifically for logging. A string so that we can use <unknown> if we don't get an address at connection time.
    peer_addr: String,
}

struct PerClientState {
    bmc_connection: BmcConnectionSubscription,
    // Option so that it can be taken with .take() when we get a shell_request or exec_request
    client_channel: Option<Channel<Msg>>,
}

impl Handler {
    pub fn new(
        bmc_connection_store: BmcConnectionStore,
        config: Arc<Config>,
        forge_api_client: ForgeApiClient,
        metrics: Arc<ServerMetrics>,
        peer_addr: Option<SocketAddr>,
    ) -> Self {
        tracing::debug!("spawning new frontend connection handler");
        Self {
            config,
            forge_api_client,
            bmc_connection_store,
            authenticated_user: None,
            per_client_state: HashMap::new(),
            metrics,
            last_auth_failure: Default::default(),
            peer_addr: peer_addr
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "<unknown>".to_string()),
        }
    }

    fn get_client_state_or_report_error(
        &mut self,
        session: &mut Session,
        channel_id: ChannelId,
    ) -> Option<&mut PerClientState> {
        if let Some(state) = self.per_client_state.get_mut(&channel_id) {
            return Some(state);
        }

        tracing::error!(self.peer_addr, "Request on unknown channel");
        session.channel_failure(channel_id).ok();
        session
            .data(channel_id, "ssh-console error: Unknown channel\n".into())
            .ok();
        session.close(channel_id).ok();
        None
    }
}

impl Drop for Handler {
    fn drop(&mut self) {
        tracing::info!(self.peer_addr, "end frontend connection");
        // All auth failure paths set self.last_auth_failure, but auth can still succeed (they may
        // be trying multiple pubkeys, etc.) So if authenticated_user is None but last_auth_failure
        // is Some, bump the metrics.
        if let (None, Some(last_auth_failure)) = (&self.authenticated_user, &self.last_auth_failure)
        {
            tracing::warn!(
                self.peer_addr,
                "authentication failed for user: {}",
                last_auth_failure.user()
            );
            self.metrics
                .client_auth_failures_total
                .add(1, last_auth_failure.metric());
        }
    }
}

impl russh::server::Handler for Handler {
    type Error = RusshOrEyreError;

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        tracing::trace!(self.peer_addr, "channel_open_session");
        let Some(user) = &self.authenticated_user else {
            return Err(eyre::format_err!(
                "BUG: channel_open_session called but we don't have an authenticated user"
            )
            .into());
        };

        // fetch the BMC connection
        let channel_id = channel.id();
        let bmc_connection = self
            .bmc_connection_store
            .get_connection(
                user,
                &self.config,
                &self.forge_api_client,
                self.metrics.clone(),
            )
            .await
            .with_context(|| format!("could not get BMC connection for {user}"))?;

        // Save the BMC and client channel in self, so the Handler methods can find it
        self.per_client_state.insert(
            channel_id,
            PerClientState {
                bmc_connection,
                client_channel: Some(channel),
            },
        );

        session
            .channel_success(channel_id)
            .context("error replying with success to channel_open_session")?;

        Ok(true)
    }

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        tracing::trace!(self.peer_addr, "auth_none");
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
        tracing::trace!(self.peer_addr, "auth_openssh_certificate");
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
                self.peer_addr,
                user,
                "openssh certificate CA certificate not trusted, rejecting authentication"
            );
            self.last_auth_failure = Some(AuthFailureReason::Certificate {
                user: user.to_owned(),
            });
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        if !certificate_contains_role(certificate, &self.config.admin_certificate_role) {
            tracing::warn!(
                self.peer_addr,
                "certificate auth failed for user {user}, not in role {}",
                &self.config.admin_certificate_role
            );
            self.last_auth_failure = Some(AuthFailureReason::Certificate {
                user: user.to_owned(),
            });
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }

        tracing::info!(
            self.peer_addr,
            "certificate auth succeeded for user {user}, in role {}",
            &self.config.admin_certificate_role
        );
        self.authenticated_user = Some(user.to_owned());
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        tracing::trace!(self.peer_addr, "auth_publickey");
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
            tracing::debug!(self.peer_addr, user, "rejecting public key for user {user}");
            false
        };

        let success = if !success && self.config.insecure {
            tracing::info!(
                self.peer_addr,
                "Overriding public-key rejection because we are in insecure (testing) mode"
            );
            true
        } else {
            success
        };

        if success {
            self.authenticated_user = Some(user.to_owned());
            Ok(Auth::Accept)
        } else {
            self.last_auth_failure = Some(AuthFailureReason::PubKey {
                user: user.to_owned(),
            });
            Ok(Auth::Reject {
                partial_success: false,
                proceed_with_methods: None,
            })
        }
    }

    /// Forward the data to the BMC
    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::trace!(self.peer_addr, "data");
        if let Some(client_state) = self.get_client_state_or_report_error(session, channel) {
            client_state
                .bmc_connection
                .to_bmc_msg_tx
                .send(ChannelMsgOrExec::ChannelMsg(ChannelMsg::Data {
                    data: data.to_vec().into(),
                }))
                .await
                .context("error writing data to channel")?;
        }
        Ok(())
    }

    /// Forward the data to the BMC
    async fn extended_data(
        &mut self,
        channel: ChannelId,
        code: u32,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::trace!(self.peer_addr, "extended_data");
        if let Some(client_state) = self.get_client_state_or_report_error(session, channel) {
            client_state
                .bmc_connection
                .to_bmc_msg_tx
                .send(ChannelMsgOrExec::ChannelMsg(ChannelMsg::ExtendedData {
                    data: data.to_vec().into(),
                    ext: code,
                }))
                .await
                .context("error writing extended_data to channel")?;
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::trace!(self.peer_addr, "pty_request");
        if let Some(client_state) = self.get_client_state_or_report_error(session, channel) {
            client_state
                .bmc_connection
                .to_bmc_msg_tx
                .send(ChannelMsgOrExec::ChannelMsg(ChannelMsg::RequestPty {
                    want_reply: false,
                    term: term.to_string(),
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    terminal_modes: modes.to_vec(),
                }))
                .await
                .context("error sending pty request to BMC")?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::trace!(self.peer_addr, "shell_request");
        let peer_addr = self.peer_addr.clone();
        let Some(client_state) = self.get_client_state_or_report_error(session, channel_id) else {
            return Ok(());
        };

        // shell requests are when we actually subscribe to the BMC connection. We have to take
        // ownership of the client channel here so that we can drop it when they disconnect, which
        // means we can't support both a shell_request and an exec_request on the same channel
        // (which makes sense.)
        let Some(channel) = client_state.client_channel.take() else {
            tracing::error!(
                self.peer_addr,
                "Channel unavailable, cannot service shell request"
            );
            session.channel_failure(channel_id).ok();
            session
                .data(
                    channel_id,
                    "ssh-console error: Channel unavailable\r\n".into(),
                )
                .ok();
            session.close(channel_id).ok();
            return Ok(());
        };
        let machine_id = client_state.bmc_connection.machine_id;
        let Some(from_bmc_rx) = client_state
            .bmc_connection
            .to_frontend_msg_weak_tx
            .upgrade()
            .map(|tx| tx.subscribe())
        else {
            return Err(eyre::format_err!(
                "BMC connection for {machine_id} dropped before we could subscribe to messages"
            )
            .into());
        };

        // Proxy messages from the BMC to the user's connection
        // NOTE: We have to go through extra effort to know when to stop proxying messages, because
        // we don't get reliably told when clients disconnect. So we poll for channel_rx here
        // (taking ownership of it) and signal a shutdown of the proxy loop, then when that happens,
        // we finally close the channel. Only then is Self::channel_close() actually sent! (This is
        // IMO a design flaw in russh.)
        let (mut channel_rx, channel_tx) = channel.split();
        let proxy_handle = message_proxy::spawn(from_bmc_rx, channel_tx, peer_addr);

        // Wait for the channel to close, then stop the proxy loop.
        tokio::spawn(async move {
            loop {
                if channel_rx.wait().await.is_none() {
                    break;
                }
            }
            proxy_handle.shutdown_and_wait().await;
        });

        let banner = match client_state.bmc_connection.kind {
            Kind::Ssh => BANNER_SSH_BMC.as_bytes(),
            Kind::Ipmi => BANNER_IPMI_BMC.as_bytes(),
        };
        session.data(channel_id, banner.into()).ok();
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::trace!(self.peer_addr, "exec_request");
        let Some(PerClientState {
            client_channel,
            bmc_connection,
        }) = self.get_client_state_or_report_error(session, channel_id)
        else {
            return Ok(());
        };

        // Drop the client channel when we're done, so that it properly disconnects.
        let Some(channel) = client_channel.take() else {
            tracing::error!(
                self.peer_addr,
                "Channel unavailable, cannot service exec request"
            );
            session.channel_failure(channel_id).ok();
            session
                .data(
                    channel_id,
                    "ssh-console error: Channel unavailable\r\n".into(),
                )
                .ok();
            session.close(channel_id).ok();
            return Ok(());
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        bmc_connection
            .to_bmc_msg_tx
            .send(ChannelMsgOrExec::Exec {
                command: data.to_vec(),
                reply_tx,
            })
            .await
            .context("error sending exec request to BMC")?;

        tokio::select! {
            _ = tokio::time::sleep(EXEC_TIMEOUT) => {
                    channel
                        .data(b"Error: request timeout\r\n".as_slice())
                        .await
                        .ok();
                    channel.exit_status(1).await.ok();
            }
            res = reply_rx => match res {
                Ok(ExecReply {
                    output,
                    exit_status,
                }) => {
                    channel.data(output.as_slice()).await.ok();
                    channel.exit_status(exit_status).await.ok();
                }
                Err(_) => {
                    channel
                        .data(b"Error: BMC disconnected\r\n".as_slice())
                        .await
                        .ok();
                    channel.exit_status(1).await.ok();
                }
            }
        }

        session.channel_success(channel_id).ok();
        channel.close().await.ok();

        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        tracing::trace!(self.peer_addr, "window_change_request");
        if let Some(client_state) = self.get_client_state_or_report_error(session, channel) {
            client_state
                .bmc_connection
                .to_bmc_msg_tx
                .send(ChannelMsgOrExec::ChannelMsg(ChannelMsg::WindowChange {
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                }))
                .await
                .context("error sending window change request to BMC")?;
        }
        Ok(())
    }
}

/// The error type used by Handler, so that we can distinguish between Russh errors and our errors.
#[derive(Debug)]
pub enum RusshOrEyreError {
    Russh(russh::Error),
    Eyre(eyre::Error),
}

impl fmt::Display for RusshOrEyreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RusshOrEyreError::Russh(e) => fmt::Display::fmt(e, f),
            RusshOrEyreError::Eyre(e) => fmt::Display::fmt(e, f),
        }
    }
}

impl std::error::Error for RusshOrEyreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RusshOrEyreError::Russh(e) => e.source(),
            RusshOrEyreError::Eyre(e) => e.source(),
        }
    }
}

impl From<eyre::Error> for RusshOrEyreError {
    fn from(value: eyre::Error) -> Self {
        RusshOrEyreError::Eyre(value)
    }
}

impl From<russh::Error> for RusshOrEyreError {
    fn from(value: russh::Error) -> Self {
        RusshOrEyreError::Russh(value)
    }
}

/// Indicates the reason auth may have failed. This is so we can avoid logging warnings about failed authentication if only the first method (pubkey) failed but the second succeeded.
enum AuthFailureReason {
    PubKey { user: String },
    Certificate { user: String },
}

impl AuthFailureReason {
    fn metric(&self) -> &'static [opentelemetry::KeyValue] {
        match self {
            AuthFailureReason::PubKey { .. } => PUBKEY_AUTH_FAILURE_METRIC.as_slice(),
            AuthFailureReason::Certificate { .. } => CERT_AUTH_FAILURE_METRIC.as_slice(),
        }
    }

    fn user(&self) -> &str {
        match self {
            AuthFailureReason::PubKey { user, .. } => user,
            AuthFailureReason::Certificate { user, .. } => user,
        }
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
                tracing::debug!(
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
                // Any other error, we should just reject, even if the config overrides it, to stop
                // bugs.
                return Err(e).context(format!(
                    "Unexpected error calling carbide-api to validate pubkey for {user}: {code}"
                ));
            }
        },
    };

    Ok(authorized)
}
