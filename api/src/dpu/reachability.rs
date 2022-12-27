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
}

pub type ReachabilityResult<T> = Result<T, ReachabilityError>;

// Trait to implement various conditions to validate if DPU is in acceptable state (UP or Down).
#[async_trait]
pub trait Reachability {
    // Method to check if DPU is reachable.
    async fn is_reachable(&self) -> ReachabilityResult<bool>;

    // Reachable is not always means that condition is matched. We need to revert reachability in
    // case to check if DPU is down.
    async fn await_condition(&self) -> ReachabilityResult<()>;
}

pub async fn wait_for_requested_state(
    duration: Duration,
    handler: impl Reachability,
) -> ReachabilityResult<()> {
    match tokio::time::timeout(duration, handler.await_condition()).await {
        Err(_) => Err(ReachabilityError::TokioTimeout),
        Ok(result) => result,
    }
}

pub enum State {
    Alive,
    Dead,
}
pub struct PingReachabilityChecker {
    host: IpAddr,
    state: State,
}

impl PingReachabilityChecker {
    pub fn new(host: IpAddr, state: State) -> Self {
        PingReachabilityChecker { host, state }
    }
}

#[async_trait]
impl Reachability for PingReachabilityChecker {
    async fn is_reachable(&self) -> ReachabilityResult<bool> {
        let host = self.host.to_string();
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

        Ok(status
            .map_err(|err| ReachabilityError::ReachabilityCheckError(err.to_string()))?
            .success())
    }

    async fn await_condition(&self) -> ReachabilityResult<()> {
        loop {
            let reachable = self.is_reachable().await?;
            match self.state {
                State::Dead => {
                    if reachable {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    } else {
                        return Ok(());
                    }
                }

                State::Alive => {
                    if !reachable {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    } else {
                        return Ok(());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[tokio::test]
    async fn test_wait_for_dpu_down() {
        assert!(wait_for_requested_state(
            Duration::from_secs(5),
            PingReachabilityChecker::new(
                IpAddr::V4(Ipv4Addr::new(
                    255, 123, 253, 5, // Some random IP which is not reachable from system
                )),
                State::Dead,
            ),
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_dpu_down_fail() {
        assert!(wait_for_requested_state(
            Duration::from_secs(2),
            PingReachabilityChecker::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1,)), State::Dead,),
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn test_wait_for_dpu_up() {
        assert!(wait_for_requested_state(
            Duration::from_secs(5),
            PingReachabilityChecker::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1,)), State::Alive,),
        )
        .await
        .is_ok());
    }

    #[tokio::test]
    async fn test_wait_for_dpu_up_fail() {
        assert!(wait_for_requested_state(
            Duration::from_secs(2),
            PingReachabilityChecker::new(
                IpAddr::V4(Ipv4Addr::new(
                    255, 123, 253, 5, // Some random IP which is not reachable from system
                )),
                State::Alive,
            ),
        )
        .await
        .is_err());
    }
}
