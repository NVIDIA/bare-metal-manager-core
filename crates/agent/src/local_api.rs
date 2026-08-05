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

//! The dpu-agent's local API: an `AgentLocal` gRPC service on a unix socket,
//! by default in a dedicated `run/` subdirectory of the shared `/opt/forge`
//! credentials directory (issue #355) — so containerized consumers mount the
//! socket read-write while the credentials stay on a read-only mount.
//!
//! This is the consolidation point for agent <-> co-located-service
//! communication on the DPU. First RPC: `GetNodeToken`, which hands
//! co-located NICo services (fmds, …) a short-lived node-auth bearer JWT so
//! they can authenticate to nico-api without mounting the machine's private
//! key — only the agent ever touches the key. Future local needs should add
//! RPCs here rather than new sockets, ports, or file drops.

use std::sync::Arc;

use ::rpc::agent_local::agent_local_server::{AgentLocal, AgentLocalServer};
use ::rpc::agent_local::{GetNodeTokenRequest, GetNodeTokenResponse};
use ::rpc::node_jwt::NodeJwtMinter;
use eyre::WrapErr;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

struct AgentLocalService {
    minter: Arc<NodeJwtMinter>,
}

#[tonic::async_trait]
impl AgentLocal for AgentLocalService {
    async fn get_node_token(
        &self,
        _request: Request<GetNodeTokenRequest>,
    ) -> Result<Response<GetNodeTokenResponse>, Status> {
        // Minting reads the cert/key from disk on cache miss — cheap enough to
        // do inline, and it means the endpoint starts working the moment the
        // machine certificate lands without any coordination.
        match self.minter.current_with_expiry() {
            Some((token, expires_at)) => {
                Ok(Response::new(GetNodeTokenResponse { token, expires_at }))
            }
            None => Err(Status::unavailable(
                "no node token available yet; machine certificate not present or unreadable",
            )),
        }
    }
}

/// Prepares the socket's parent directory, which must be dedicated to this
/// socket and nothing else.
///
/// The directory has to be unreachable to other users *before* `bind`: `bind`
/// creates the socket with umask-derived permissions — typically
/// world-connectable — and the 0600 chmod only lands afterwards. The listener
/// is already bound in that window, so a connection from any local user would
/// queue in the backlog and be served a full machine identity the moment
/// accepting starts. An unreachable parent closes the window; the socket's own
/// 0600 is then defence in depth.
///
/// But `local-api-socket` is operator-configurable, so applying 0700 to
/// whatever the parent happens to be is its own hazard: `/run/agent.sock`
/// would take `/run` to 0700 and lock every non-root service on the box out of
/// its runtime files. Only a directory this function created, or one holding
/// nothing but this socket, is ours to restrict — anything else is rejected
/// with an actionable message rather than silently modified.
fn prepare_socket_dir(dir: &std::path::Path, socket_path: &str) -> eyre::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    if !dir.exists() {
        // Ancestors keep their normal modes; only the socket directory itself
        // is created restricted, and created that way from the first instant
        // rather than chmod-ed after the fact.
        if let Some(ancestor) = dir.parent() {
            std::fs::create_dir_all(ancestor)
                .wrap_err(format!("creating socket directory {}", ancestor.display()))?;
        }
        return std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .wrap_err(format!("creating socket directory {}", dir.display()));
    }

    let socket_name = std::path::Path::new(socket_path).file_name();
    for entry in
        std::fs::read_dir(dir).wrap_err(format!("reading socket directory {}", dir.display()))?
    {
        let entry = entry.wrap_err(format!("reading socket directory {}", dir.display()))?;
        let name = entry.file_name();
        if socket_name != Some(name.as_os_str()) {
            eyre::bail!(
                "socket directory {} is shared with other files (found {}); \
                 point local-api-socket at a directory used for nothing else, \
                 so restricting it to 0700 cannot lock other services out",
                dir.display(),
                name.to_string_lossy()
            );
        }
    }

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).wrap_err(format!(
        "restricting socket directory permissions on {}",
        dir.display()
    ))
}

/// Binds the local API socket and serves until the process exits. The socket
/// is created mode 0600 (root-only): every legitimate consumer on the DPU
/// runs as root, and nothing else on the shared directory should be able to
/// obtain machine credentials.
///
/// Deployment-agnostic: containerized (DPF) the socket lands on the mounted
/// `/opt/forge` volume; as a plain service on DPU OS (non-DPF) the parent
/// directory is created if the agent starts before anything else touched it.
pub async fn serve(minter: Arc<NodeJwtMinter>, socket_path: &str) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = std::path::Path::new(socket_path).parent() {
        prepare_socket_dir(parent, socket_path)?;
    }
    // Remove a stale socket from a previous run; bind() fails on an existing
    // path even when nothing is listening.
    match std::fs::remove_file(socket_path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).wrap_err(format!("removing stale socket {socket_path}")),
    }

    let listener = tokio::net::UnixListener::bind(socket_path)
        .wrap_err(format!("binding agent local API socket {socket_path}"))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
        .wrap_err(format!("restricting socket permissions on {socket_path}"))?;
    tracing::info!(target: "node_auth", socket = %socket_path, "node-auth: serving agent local API (node tokens)");

    tonic::transport::Server::builder()
        .add_service(AgentLocalServer::new(AgentLocalService { minter }))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await
        .wrap_err("agent local API server exited")
}

#[cfg(test)]
mod tests {
    use ::rpc::node_jwt::NodeTokenProvider;
    use ::rpc::node_token_socket::SocketTokenSource;

    use super::*;

    const SPIFFE_URI: &str = "spiffe://forge.local/forge-system/machine/fm100xtest";

    fn write_cert_and_key(dir: &tempfile::TempDir) -> (String, String) {
        let mut params = rcgen::CertificateParams::default();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(SPIFFE_URI.to_string()).expect("uri"),
        )];
        let key = rcgen::KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key).expect("certificate");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("cert.key");
        std::fs::write(&cert_path, cert.pem()).expect("write cert");
        std::fs::write(&key_path, key.serialize_pem()).expect("write key");
        (
            cert_path.to_string_lossy().into_owned(),
            key_path.to_string_lossy().into_owned(),
        )
    }

    /// End-to-end broker flow: agent serves tokens minted from the machine
    /// cert; a key-less consumer obtains one through `SocketTokenSource`.
    #[tokio::test]
    async fn keyless_consumer_gets_token_via_socket() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path) = write_cert_and_key(&dir);
        // Its own subdirectory, as in production (`<certsDir>/run/agent.sock`):
        // the socket never shares a directory with the credentials.
        let socket = dir.path().join("run").join("agent.sock");
        let socket_str = socket.to_string_lossy().into_owned();

        let minter = NodeJwtMinter::new(cert_path, key_path);
        let expected = minter.current().expect("agent side can mint");
        tokio::spawn({
            let socket_str = socket_str.clone();
            async move { serve(minter, &socket_str).await }
        });

        let source = SocketTokenSource::spawn(socket_str);
        let mut got = None;
        for _ in 0..100 {
            if let Some(token) = source.current() {
                got = Some(token);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(got.as_deref(), Some(expected.as_str()));
    }

    #[tokio::test]
    async fn socket_is_root_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path) = write_cert_and_key(&dir);
        let socket = dir.path().join("run").join("agent.sock");
        let socket_str = socket.to_string_lossy().into_owned();

        tokio::spawn({
            let socket_str = socket_str.clone();
            async move { serve(NodeJwtMinter::new(cert_path, key_path), &socket_str).await }
        });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let mode = std::fs::metadata(&socket)
            .expect("socket metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    /// The socket's own mode is applied only after `bind`, so the directory is
    /// what actually keeps other users out during that window. Anyone who got
    /// in would be handed a full machine identity.
    #[tokio::test]
    async fn socket_directory_is_root_only_before_the_socket_exists() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let (cert_path, key_path) = write_cert_and_key(&dir);
        // A pre-existing, world-traversable directory: the agent must tighten
        // it rather than assume a fresh one.
        let run_dir = dir.path().join("run");
        std::fs::create_dir(&run_dir).expect("create run dir");
        std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o755))
            .expect("loosen run dir");
        let socket = run_dir.join("agent.sock");
        let socket_str = socket.to_string_lossy().into_owned();

        tokio::spawn({
            let socket_str = socket_str.clone();
            async move { serve(NodeJwtMinter::new(cert_path, key_path), &socket_str).await }
        });
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        let mode = std::fs::metadata(&run_dir)
            .expect("run dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "socket directory must exclude other users");
    }

    /// Tightening the parent is only safe when the parent belongs to us.
    /// `local-api-socket = /run/agent.sock` would otherwise take `/run` to
    /// 0700 and lock every non-root service on the box out of its runtime
    /// files, so a directory holding anything else is refused outright.
    #[test]
    fn shared_socket_directory_is_refused_rather_than_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let shared = dir.path().join("run");
        std::fs::create_dir(&shared).expect("create shared dir");
        std::fs::write(shared.join("someone-elses.pid"), b"1234").expect("write neighbour");
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755))
            .expect("loosen shared dir");
        let socket = shared.join("agent.sock");

        let err = prepare_socket_dir(&shared, &socket.to_string_lossy())
            .expect_err("a shared directory must not be accepted");
        assert!(
            err.to_string().contains("someone-elses.pid"),
            "the error should name the file that made it shared, got: {err}"
        );

        let mode = std::fs::metadata(&shared)
            .expect("shared dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o755,
            "a refused directory must be left exactly as it was found"
        );
    }

    /// A directory we create ourselves is restricted from its first instant,
    /// with no window at a looser mode for anyone to slip through.
    #[test]
    fn fresh_socket_directory_is_created_root_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let run_dir = dir.path().join("nested").join("run");
        let socket = run_dir.join("agent.sock");

        prepare_socket_dir(&run_dir, &socket.to_string_lossy()).expect("prepare fresh dir");

        let mode = std::fs::metadata(&run_dir)
            .expect("run dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "a freshly created socket directory is 0700");
    }

    /// The stale socket from a previous run is ours, so it must not be
    /// mistaken for a neighbour and block startup.
    #[test]
    fn a_stale_socket_does_not_make_the_directory_look_shared() {
        let dir = tempfile::tempdir().expect("tempdir");
        let run_dir = dir.path().join("run");
        std::fs::create_dir(&run_dir).expect("create run dir");
        let socket = run_dir.join("agent.sock");
        std::fs::write(&socket, b"").expect("stale socket");

        prepare_socket_dir(&run_dir, &socket.to_string_lossy())
            .expect("a directory holding only our own socket is still dedicated");
    }
}
