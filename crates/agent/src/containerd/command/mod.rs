pub mod bash_command;

#[async_trait::async_trait]
pub trait Command: std::fmt::Debug + Send + Sync {
    async fn run(&mut self) -> eyre::Result<String>;
}
