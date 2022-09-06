use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::{Path, PathBuf};
use std::{fs, io};

use rand::Rng;
use reqwest::Client;
use rocket::futures::stream::FuturesUnordered;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use async_compression::tokio::write::GzipDecoder;
use futures_util::stream::StreamExt;
use tokio_tar::Archive;

#[derive(thiserror::Error, Debug)]
pub enum ArtifactConfigReadError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Deserialize(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Deserialize)]
pub enum Architecture {
    Aarch64,
    X84_64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Authorization {
    pub user: String,
    pub token: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Artifact {
    pub url: String,
    pub architecture: Architecture,
    pub checksums: HashMap<String, String>,
}

// we intentionally didn't derive Debug,
// so that we didn't inadvertently print the authorization secrets to the logs
#[derive(Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ArtifactConfig {
    pub forge_boot_artifact_aarch64: Artifact,
    pub forge_user_data_artifact_aarch64: Artifact,
    #[serde(skip)]
    pub artifact_authorization: Option<Authorization>,
}

impl Display for ArtifactConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "forge_boot_artifact_aarch64: {:#?}\nforge_user_data_artifact_aarch64: {:#?}",
            self.forge_boot_artifact_aarch64, self.forge_user_data_artifact_aarch64
        )
    }
}

impl ArtifactConfig {
    pub fn from_config_file<P: AsRef<Path>>(
        configuration_file_path: P,
    ) -> Result<Self, ArtifactConfigReadError> {
        let json_string = fs::read_to_string(configuration_file_path)?;
        let mut config = serde_json::from_str::<ArtifactConfig>(json_string.as_str())?;

        if let (Ok(user), Ok(token)) = (
            std::env::var("ARTIFACT_AUTHORIZATION_USER"),
            std::env::var("ARTIFACT_AUTHORIZATION_TOKEN"),
        ) {
            if !user.is_empty() && !token.is_empty() {
                config.artifact_authorization = Some(Authorization { user, token });
            }
        }

        Ok(config)
    }

    pub async fn validate_artifacts<P>(
        self,
        required_artifact_path: P,
    ) -> Result<(), Box<dyn Error>>
    where
        P: AsRef<Path> + Clone,
    {
        let client = Client::new();

        let mut futures = vec![];
        let required_artifact_path = required_artifact_path.as_ref().to_owned();

        let required_artifact_path_clone = required_artifact_path.clone();
        let forge_boot_artifact_aarch64_clone = self.forge_boot_artifact_aarch64.clone();
        if !tokio::task::spawn_blocking(move || {
            validate_artifact(
                required_artifact_path_clone,
                &forge_boot_artifact_aarch64_clone,
            )
        })
        .await?
        {
            match self.artifact_authorization.as_ref() {
                Some(authorization) => {
                    eprintln!(
                        "unable to validate artifact: forge_boot_artifact_aarch64, downloading it"
                    );
                    let boot_artifacts_fut = download_artifact(
                        self.forge_boot_artifact_aarch64,
                        authorization.clone(),
                        client.clone(),
                        required_artifact_path.clone(),
                    );

                    futures.push(boot_artifacts_fut);
                }
                None => {
                    return Err(ArtifactDownloadError::MissingAuthorization.into());
                }
            }
        }
        let required_artifact_path_clone = required_artifact_path.clone();
        let forge_user_data_artifact_aarch64_clone = self.forge_user_data_artifact_aarch64.clone();
        if !tokio::task::spawn_blocking(move || {
            validate_artifact(
                required_artifact_path_clone,
                &forge_user_data_artifact_aarch64_clone,
            )
        })
        .await?
        {
            match self.artifact_authorization.as_ref() {
                Some(authorization) => {
                    eprintln!(
                        "unable to validate artifact: forge_user_data_artifact_aarch64, downloading it"
                    );
                    let user_data_artifacts_fut = download_artifact(
                        self.forge_user_data_artifact_aarch64.clone(),
                        authorization.clone(),
                        client,
                        required_artifact_path,
                    );
                    futures.push(user_data_artifacts_fut);
                }
                None => {
                    return Err(ArtifactDownloadError::MissingAuthorization.into());
                }
            }
        }

        if futures.is_empty() {
            println!("Artifacts were already present, continuing startup.");
            return Ok(());
        }

        let futures: FuturesUnordered<_> = futures.into_iter().collect();

        let results: Vec<Result<(), ArtifactDownloadError>> = futures.collect().await;

        results
            .into_iter()
            .collect::<Result<(), ArtifactDownloadError>>()
            .map_err(|err| err.into())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ArtifactDownloadError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("{0}")]
    RequestFailed(String),
    #[error("authorization was required but credentials are missing")]
    MissingAuthorization,
}

async fn download_artifact<P>(
    artifact: Artifact,
    authorization: Authorization,
    client: Client,
    final_file_path: P,
) -> Result<(), ArtifactDownloadError>
where
    P: AsRef<Path>,
{
    let request = client
        .get(&artifact.url)
        .basic_auth(&authorization.user, Some(&authorization.token))
        .build()?;

    match client.execute(request).await {
        Ok(response) if response.status().is_success() => {
            let mut stream = response.bytes_stream();

            let random_number: u32 = {
                let mut rng = rand::thread_rng();
                rng.gen()
            };
            let archive_location = format!("/tmp/output_location-{}.tar", random_number);
            let output_location = tokio::fs::File::create(&archive_location).await?;

            let mut gzip_decoder = GzipDecoder::new(output_location);
            while let Some(chunk) = stream.next().await {
                let bytes = chunk?.to_vec();
                gzip_decoder.write_all(&bytes).await?;
            }

            let _ = gzip_decoder.flush().await;

            let full_artifact_path = get_full_artifact_path(&artifact, final_file_path);
            // we need to remove the existing files as the archive unpacking will fail if any are present
            for file_name in artifact.checksums.keys() {
                match tokio::fs::remove_file(full_artifact_path.join(file_name)).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(ArtifactDownloadError::Io(error));
                    }
                }
            }

            // ideally i could do this in one go,
            // but the api exposed by the archive lib wants a reader
            // and I only have a writer after the file is on disk.
            let archived_file = tokio::fs::File::open(&archive_location).await?;
            let mut archive = Archive::new(archived_file);
            archive.unpack(&full_artifact_path).await?;

            tokio::fs::remove_file(&archive_location).await?;
        }
        Ok(response) => {
            // actual response from server was bad, we should retry this
            let response_error_str =
                String::from_utf8_lossy(response.bytes().await?.to_vec().as_slice()).to_string();
            return Err(ArtifactDownloadError::RequestFailed(response_error_str));
        }
        Err(error) => {
            // http client error, probably borked but we should retry this
            return Err(ArtifactDownloadError::Reqwest(error));
        }
    }
    Ok(())
}

fn get_full_artifact_path<P>(artifact: &Artifact, artifact_file_path: P) -> PathBuf
where
    P: AsRef<Path>,
{
    let arch_string = match artifact.architecture {
        Architecture::Aarch64 => "aarch64",
        Architecture::X84_64 => "x86_64",
    };

    artifact_file_path
        .as_ref()
        .join("blobs")
        .join("internal")
        .join(arch_string)
}

pub fn validate_artifact<P>(required_artifact_path: P, artifact: &Artifact) -> bool
where
    P: AsRef<Path>,
{
    let path = get_full_artifact_path(artifact, required_artifact_path);
    for (file_name, checksum) in artifact.checksums.iter() {
        let mut hasher = Sha256::new();
        match fs::File::open(path.join(file_name)) {
            Ok(mut file) => {
                match io::copy(&mut file, &mut hasher) {
                    Ok(_bytes_written) => {
                        let hash_bytes = hasher.finalize();
                        let hex_hash = hex::encode(hash_bytes);

                        if hex_hash.as_str() == checksum.as_str() {
                            continue; //valid file
                        } else {
                            eprintln!(
                                "artifact file checksum mismatch! file_name: {} expected: {} actual: {}",
                                file_name, checksum, hex_hash
                            );
                            return false;
                        }
                    }
                    Err(error) => {
                        eprintln!(
                            "unable to calculate hash for artifact file: {} with error: {:?}",
                            file_name, error
                        );
                        return false;
                    }
                }
            }
            Err(error) => {
                eprintln!(
                    "unable to open artifact file: {} with error: {:?}",
                    file_name, error
                );
                return false;
            }
        }
    }

    true
}
