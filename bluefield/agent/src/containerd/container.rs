use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use lazy_static::lazy_static;
use serde;
use serde::{Deserialize, Serialize};
use serde_json;
use tokio::sync::Mutex;
use tracing::log::error;

use crate::containerd::command::cache::CommandCache;
use crate::containerd::image::{Image, ImageNameComponent};
use crate::containerd::BashCommand;

lazy_static! {
    pub static ref COMMAND_CACHE: Arc<Mutex<CommandCache>> =
        Arc::new(Mutex::new(CommandCache::new()));
}

/// A containers metadata
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerMetadata {
    pub name: String,
    pub attempt: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerState {
    #[serde(rename(deserialize = "CONTAINER_RUNNING"))]
    Running,
    #[serde(rename(deserialize = "CONTAINER_EXITED"))]
    Exited,
}

/// An image associated with a container that is running or has terminated
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerImage {
    #[serde(rename = "image")]
    pub id: String,
    pub annotations: HashMap<String, String>,
}

/// A container deserialized with additional information for convenience
/// The container needs to be running or have terminated
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerSummary {
    pub id: String,
    #[serde(rename = "podSandboxId")]
    pub sandbox_id: String,
    pub metadata: ContainerMetadata,
    pub image: ContainerImage,
    #[serde(rename = "imageRef")]
    #[serde(default, skip_deserializing)]
    pub image_ref: Vec<ImageNameComponent>,
    // We skip this during deserialize because we will populate it later
    pub state: ContainerState,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

/// A list of Container Images that are present on a system
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Images {
    pub images: Vec<Image>,
}

/// A list of running or terminated containers on a system
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Containers {
    pub containers: Vec<ContainerSummary>,
}

impl FromIterator<Image> for Images {
    fn from_iter<I: IntoIterator<Item = Image>>(iter: I) -> Self {
        Images {
            images: iter.into_iter().collect(),
        }
    }
}

impl Images {
    pub async fn list() -> eyre::Result<Images> {
        let data = get_container_images().await?;
        serde_json::from_str::<Images>(&data).map_err(|err| eyre::eyre!(err))
    }

    pub fn filter_by_name<T>(self, name: T) -> eyre::Result<Images>
    where
        T: AsRef<str>,
    {
        let filtered = self
            .images
            .into_iter()
            .filter(|x| x.names.iter().any(|y| y.name.contains(name.as_ref())))
            .collect();
        Ok(filtered)
    }

    pub fn find_by_name<T>(self, name: T) -> eyre::Result<Image>
    where
        T: AsRef<str>,
    {
        self.images
            .into_iter()
            .find(|x| x.names.iter().any(|y| y.name.contains(name.as_ref())))
            .ok_or_else(|| eyre::eyre!("Could not find container image for name {}", name.as_ref()))
    }

    pub fn find_by_id<T>(self, container_id: T) -> eyre::Result<Image>
    where
        T: AsRef<str>,
        T: PartialEq,
    {
        self.images
            .into_iter()
            .find(|x| x.id == container_id.as_ref())
            .ok_or_else(|| {
                eyre::eyre!(
                    "Could not find container image for id {}",
                    container_id.as_ref()
                )
            })
    }
}

impl Containers {
    pub async fn list() -> eyre::Result<Self> {
        let data = get_containers().await?;

        let containers = serde_json::from_str::<Containers>(&data)
            .map_err(|e| eyre::eyre!(e))?
            .containers;

        Ok(Containers { containers })
    }

    pub fn find_by_name<T>(self, name: T) -> eyre::Result<ContainerSummary>
    where
        T: AsRef<str>,
        T: PartialEq,
    {
        self.containers
            .into_iter()
            .find(|x| x.metadata.name == name.as_ref())
            .ok_or_else(|| eyre::eyre!("Could not find container for name {}", name.as_ref()))
    }
}

/// Return a list of all container images in JSON format.
async fn get_container_images() -> eyre::Result<String> {
    if cfg!(test) || std::env::var("NO_DPU_CONTAINERS").is_ok() {
        let repo_root = PathBuf::from(std::env::var("REPO_ROOT").unwrap_or(".".to_string()));

        std::fs::read_to_string(repo_root.join("dev/docker-env/container_images.json")).map_err(
            |e| {
                error!("Could not read container_images.json: {}", e);
                eyre::eyre!("Could not read container_images.json: {}", e)
            },
        )
    } else {
        let command =
            Box::new(BashCommand::new("bash").args(vec!["-c", "critcl", "images", "-o", "json"]));
        (*COMMAND_CACHE)
            .lock()
            .await
            .get_or_insert(command)
            .await
            .map_err(|e| eyre::eyre!("Poisoned lock: {}", e))
    }
}

/// Returns a list of all containers on a host in JSON format.
async fn get_containers() -> eyre::Result<String> {
    if cfg!(test) || std::env::var("NO_DPU_CONTAINERS").is_ok() {
        let repo_root = PathBuf::from(std::env::var("REPO_ROOT").unwrap_or(".".to_string()));

        std::fs::read_to_string(repo_root.join("dev/docker-env/containers.json")).map_err(|e| {
            error!("Could not read containers.json: {}", e);
            eyre::eyre!("Could not read containers.json: {}", e)
        })
    } else {
        let command =
            Box::new(BashCommand::new("bash").args(vec!["-c", "critcl", "ps", "-a", "-o", "json"]));
        (*COMMAND_CACHE)
            .lock()
            .await
            .get_or_insert(command)
            .await
            .map_err(|e| eyre::eyre!("Poisoned lock: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    use lazy_static::lazy_static;

    use crate::containerd::image::ImageNameComponent;
    use crate::containerd::{Command, CommandWrapper};

    use super::*;

    //use serde_json;

    lazy_static! {
        pub static ref RUN_COUNTER_0: AtomicU32 = AtomicU32::new(0);
        pub static ref RUN_COUNTER_1: AtomicU32 = AtomicU32::new(0);
    }

    #[derive(Debug, Eq, PartialEq, Hash, Clone)]
    struct TestCommand {
        pub output: String,
        pub counter: usize,
    }

    // Implementation of command which increments a global counter and returns output
    #[async_trait::async_trait]
    impl Command for TestCommand {
        async fn run(&mut self) -> eyre::Result<String> {
            if self.counter == 0 {
                let _ = (*RUN_COUNTER_0).fetch_add(1, Ordering::SeqCst);
            } else {
                let _ = (*RUN_COUNTER_1).fetch_add(1, Ordering::SeqCst);
            }
            Ok(self.output.clone())
        }
    }

    #[tokio::test]
    async fn test_cached_output() {
        let mut wrap = CommandWrapper::new(
            Box::new(TestCommand {
                output: "test".to_string(),
                counter: 0,
            }),
            Duration::from_secs(1), // cache CommandWrapper for 1 sec
        );

        let _ = wrap.get().await.unwrap(); // get() calls TestCommand::run() which increments RUN_COUNTER_0
        let count1 = (*RUN_COUNTER_0).load(Ordering::SeqCst);
        let _ = wrap.get().await.unwrap(); // get() calls TestCommand::run() which increments RUN_COUNTER_0
        let count2 = (*RUN_COUNTER_0).load(Ordering::SeqCst); // matches count1 because output is cached and run() does not execute(no incrementing RUN_COUNTER_0)

        assert_eq!(count1, count2);
    }

    #[tokio::test]
    async fn test_cached_output_expire() {
        let mut wrap = CommandWrapper::new(
            Box::new(TestCommand {
                output: "test".to_string(),
                counter: 1,
            }),
            Duration::from_secs(1), // cache for 1 second
        );

        let duration = Duration::from_secs(2);

        let _ = wrap.get().await.unwrap(); // get() calls TestCommand::run() which increments RUN_COUNTER_1
        let count1 = (*RUN_COUNTER_1).load(Ordering::SeqCst); // load counter

        std::thread::sleep(duration); // sleep for 1 sec to expire cache

        let _ = wrap.get().await.unwrap();
        let count2 = (*RUN_COUNTER_1).load(Ordering::SeqCst); // get counter

        assert_ne!(count1, count2); // count1 and count2 should not match because cache1 holds the cached RUN_COUNTER_1 and count2 holds new count from TestCommand::run()
    }

    #[tokio::test]
    async fn test_container_images() {
        let container_images = get_container_images().await.unwrap();
        let json = serde_json::from_str::<Images>(&container_images).unwrap();
        assert_eq!(json.images.len(), 3);
    }

    #[tokio::test]
    async fn test_all_containers() {
        let containers = get_containers().await.unwrap();
        let json = serde_json::from_str::<Containers>(&containers).unwrap();
        assert_eq!(json.containers.len(), 5);
    }

    #[tokio::test]
    async fn test_container_image_list() {
        let container_images = Images::list().await.unwrap();
        assert_eq!(container_images.images.len(), 3);
    }

    #[tokio::test]
    async fn test_filter_container_images_by_name() {
        let container_images = Images::list().await.unwrap();
        let filtered = container_images.filter_by_name("doca_").unwrap();
        assert_eq!(filtered.images.len(), 2);
        assert_eq!(
            filtered.images[0].names[0],
            ImageNameComponent {
                repository: "nvcr.io/nvidia/doca".to_string(),
                name: "doca_hbn".to_string(),
                version: "1.5.0-doca2.2.0".to_string(),
            }
        );
        assert_eq!(
            filtered.images[1].names[0],
            ImageNameComponent {
                repository: "nvcr.io/nvidia/doca".to_string(),
                name: "doca_telemetry".to_string(),
                version: "1.14.2-doca2.2.0".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn test_find_container_by_name() {
        let containers = Containers::list().await.expect("Could not get containers");
        tracing::info!("Container: {:?}", containers);
        let container = containers.find_by_name("doca-hbn").unwrap();
        tracing::info!("Container: {:?}", container);
        assert_eq!(container.metadata.name, "doca-hbn");
        assert_eq!(container.state, ContainerState::Running);
    }

    #[tokio::test]
    async fn test_filter_and_image_version() {
        let container_images = Images::list().await.unwrap();
        let filtered = container_images.filter_by_name("doca_hbn").unwrap();
        assert_eq!(filtered.images.len(), 1);
        assert_eq!(
            filtered.images[0].names[0].version(),
            "1.5.0-doca2.2.0".to_string()
        );
    }

    #[tokio::test]
    async fn test_find_and_image_version() {
        let container_images = Images::list().await.unwrap();
        let filtered = container_images.find_by_name("doca_hbn").unwrap();
        assert_eq!(filtered.names[0].version(), "1.5.0-doca2.2.0".to_string());
    }
}
