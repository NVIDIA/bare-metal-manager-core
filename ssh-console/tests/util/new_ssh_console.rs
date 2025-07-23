use crate::util::fixtures::{
    API_CA_CERT, API_CLIENT_CERT, API_CLIENT_KEY, AUTHORIZED_KEYS_PATH, SSH_HOST_KEY,
};
use eyre::Context;
use ssh_console::ReadyHandle;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::time::Duration;
use temp_dir::TempDir;

pub async fn spawn(carbide_port: u16) -> eyre::Result<NewSshConsoleHandle> {
    let addr = {
        // Pick an open port
        let l = TcpListener::bind("127.0.0.1:0")?;
        l.local_addr()?
            .to_socket_addrs()?
            .next()
            .expect("No socket available")
    };

    let logs_dir = TempDir::new().context("error creating temp dir for console logs")?;

    let config = ssh_console::config::Config {
        listen_address: addr,
        carbide_uri: format!("https://localhost:{carbide_port}")
            .try_into()
            .expect("Invalid URI?"),
        authorized_keys_path: Some(AUTHORIZED_KEYS_PATH.clone()),
        host_key_path: SSH_HOST_KEY.clone(),
        override_bmcs: None,
        dpus: false,
        insecure: false,
        override_bmc_ssh_port: Some(2222),
        override_ipmi_port: Some(1623),
        insecure_ipmi_ciphers: true,
        forge_root_ca_path: API_CA_CERT.clone(),
        client_cert_path: API_CLIENT_CERT.clone(),
        client_key_path: API_CLIENT_KEY.clone(),
        openssh_certificate_ca_fingerprints: vec![],
        admin_certificate_role: "swngc-forge-admins".to_string(),
        api_poll_interval: Duration::from_secs(1),
        console_logging_enabled: true,
        console_logs_path: logs_dir.path().to_path_buf(),
        override_bmc_ssh_host: None,
        // Eagerly retry if the connection was only open a short while (needed for tests to avoid
        // long backoff intervals.)
        successful_connection_minimum_duration: Duration::ZERO,
    };

    let mut spawn_handle = ssh_console::spawn(config).await?;
    spawn_handle.wait_until_ready().await.ok();

    Ok(NewSshConsoleHandle {
        addr,
        // Make sure the logs dir doesn't drop.
        logs_dir,
        spawn_handle,
    })
}

pub struct NewSshConsoleHandle {
    pub addr: SocketAddr,
    pub logs_dir: TempDir,
    pub spawn_handle: ssh_console::SpawnHandle,
}
