/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::fmt;
use std::fmt::{Display, Formatter};

use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::log::trace;

/// Represents the individual components of a container image name.
/// e.g.
/// nvcr.io/nvidia/doca/doca_hbn:1.5.0-doca2.2.0
///
/// repository - nvcr.io/nvidia/doca, name - doca_hbn, version - 1.5.0-doca2.2.0
#[derive(Clone, Default, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ImageNameComponent {
    /// The repository of the container image
    pub repository: String,
    /// The name of the container image
    pub name: String,
    /// The version of the container image
    pub version: String,
}

/// A container image present on the system
#[derive(Clone, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Image {
    pub id: String,
    #[serde(rename = "repoTags")]
    #[serde(deserialize_with = "container_image_name_to_component")]
    pub names: Vec<ImageNameComponent>,
}

impl ImageNameComponent {
    pub fn repository(&self) -> String {
        self.repository.to_string()
    }

    pub fn name(&self) -> String {
        self.name.to_string()
    }

    pub fn version(&self) -> String {
        self.version.to_string()
    }
}

impl Display for ImageNameComponent {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}:{}", self.repository, self.name, self.version)
    }
}

/// When deserializing an `Image`, split the name into its components and return
/// `ImageComponentName` in place of the string
pub fn container_image_name_to_component<'de, D>(
    deserializer: D,
) -> Result<Vec<ImageNameComponent>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let vec: Vec<String> = Vec::deserialize(deserializer)?;
    let initial: Vec<ImageNameComponent> = Vec::new();

    trace!("Container name component: {vec:?}");
    vec.iter().try_fold(initial, |mut accum, value| {
        let re = Regex::new(r#"(.+)\/(.+):(.+)"#).unwrap();
        re.captures(value.as_str())
            .map(|components| {
                let image_name_component = ImageNameComponent {
                    repository: components[1].to_string(),
                    name: components[2].to_string(),
                    version: components[3].to_string(),
                };
                accum.push(image_name_component);
                accum
            })
            .ok_or(serde::de::Error::custom(
                "Could not parse image name into components",
            ))
    })
}
