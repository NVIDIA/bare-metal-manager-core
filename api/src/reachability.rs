use std::{
    net::IpAddr,
    process::{Command, Stdio},
    time::Duration,
};

use async_trait::async_trait;

#[derive(Debug, thiserror::Error, Clone)]
pub enum ReachabilityError {
    #[error("Tokio timeout before task completion.")]
    TokioTimeout,

    #[error("Error while checking reachability command. Error: {0}")]
    ReachabilityCheckError(String),

    #[error("Spawning blocking thread failed. Error: {0}")]
    SpawnBlockingThreadFailed(String),

    #[error("Host is not updated.")]
    HostNotUpdated,
}

pub type ReachabilityResult<T> = Result<T, ReachabilityError>;

// Trait to implement various conditions to validate if host is in acceptable state (UP or Down).
#[async_trait]
pub trait Reachability: Send + Sync + 'static {
    /// Method to build new instance
    fn build(&self, host: IpAddr, expected_state: ExpectedState) -> Box<dyn Reachability>;

    /// Method to check if host fulfills needed condition.
    async fn check_condition(&self) -> ReachabilityResult<bool>;

    /// Wait until check_condition returns true. `wait_for_requested_state` will check for timeout.
    async fn await_condition(&self) -> ReachabilityResult<()> {
        while !self.check_condition().await? {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }

        return Ok(());
    }
}

pub async fn wait_for_requested_state(
    duration: Duration,
    handler: Box<dyn Reachability>,
) -> ReachabilityResult<()> {
    match tokio::time::timeout(duration, handler.await_condition()).await {
        Err(_) => Err(ReachabilityError::TokioTimeout),
        Ok(result) => result,
    }
}

#[derive(Default)]
pub enum ExpectedState {
    #[default]
    Alive,
    Dead,
}

#[derive(Default)]
pub struct PingReachabilityChecker {
    host: Option<IpAddr>,
    expected_state: ExpectedState,
}

#[derive(Default)]
pub struct TestPingReachabilityChecker {}

#[async_trait]
impl Reachability for PingReachabilityChecker {
    fn build(&self, host: IpAddr, expected_state: ExpectedState) -> Box<dyn Reachability> {
        Box::new(PingReachabilityChecker {
            host: Some(host),
            expected_state,
        })
    }

    async fn check_condition(&self) -> ReachabilityResult<bool> {
        let host = self
            .host
            .ok_or(ReachabilityError::HostNotUpdated)?
            .to_string();
        let status = tokio::task::spawn_blocking(move || {
            // Should we use some library instead of Command?
            Command::new("ping")
                .stdout(Stdio::null())
                .arg("-c 1") // Send only 1 packet.
                .arg("-W 2") // If we dont get response in 2 seconds, assume host unreachable.
                .arg(host)
                .status()
        })
        .await
        .map_err(|err| ReachabilityError::SpawnBlockingThreadFailed(err.to_string()))?;

        let is_reachable = status
            .map_err(|err| ReachabilityError::ReachabilityCheckError(err.to_string()))?
            .success();

        Ok(if let ExpectedState::Alive = self.expected_state {
            is_reachable
        } else {
            !is_reachable
        })
    }
}

#[async_trait]
impl Reachability for TestPingReachabilityChecker {
    fn build(&self, _host: IpAddr, _expected_state: ExpectedState) -> Box<dyn Reachability> {
        Box::new(TestPingReachabilityChecker {})
    }

    async fn check_condition(&self) -> ReachabilityResult<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[tokio::test]
    async fn test_wait_for_host_down() {
        assert!(wait_for_requested_state(
            Duration::from_secs(5),
            PingReachabilityChecker::default().build(
                IpAddr::V4(Ipv4Addr::new(
                    255, 123, 253, 5, // Some random IP which is not reachable from system
                )),
                ExpectedState::Dead,
            ),
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_host_down_fail() {
        assert!(wait_for_requested_state(
            Duration::from_secs(2),
            PingReachabilityChecker::default().build(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1,)),
                ExpectedState::Dead,
            ),
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn test_wait_for_host_up() {
        assert!(wait_for_requested_state(
            Duration::from_secs(5),
            PingReachabilityChecker::default().build(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1,)),
                ExpectedState::Alive,
            ),
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_host_up_fail() {
        assert!(wait_for_requested_state(
            Duration::from_secs(2),
            PingReachabilityChecker::default().build(
                IpAddr::V4(Ipv4Addr::new(
                    255, 123, 253, 5, // Some random IP which is not reachable from system
                )),
                ExpectedState::Alive,
            ),
        )
        .await
        .is_err());
    }
}
