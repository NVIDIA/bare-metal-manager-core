/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Authentication module for mqttea.
//!
//! This module provides pluggable authentication for MQTT connections:
//!
//! - [`CredentialsProvider`]: Trait for providers that supply username + password
//! - [`TokenProvider`]: Trait for providers that supply only a token (e.g., OAuth2 access token)
//! - [`TokenCredentialsProvider`]: Combines a [`TokenProvider`] with a fixed username
//! - [`StaticCredentials`]: Simple static username/password credentials
//! - [`OAuth2TokenProvider`]: OAuth2 client credentials flow (requires `oauth2` feature)
//!
//! # Example with OAuth2
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use std::time::Duration;
//! use mqttea::auth::{OAuth2Config, OAuth2TokenProvider, TokenCredentialsProvider};
//! use mqttea::{MqtteaClient, ClientOptions};
//!
//! // Configure OAuth2 token provider
//! let oauth2_config = OAuth2Config::new(
//!     "https://auth.example.com/oauth/token",
//!     "my-client-id",
//!     "my-client-secret",
//!     vec!["mqtt:publish".into()],
//!     Duration::from_secs(30),
//! );
//!
//! let token_provider = OAuth2TokenProvider::new(oauth2_config)?;
//!
//! // Combine with MQTT username
//! let credentials_provider = TokenCredentialsProvider::new(token_provider, "oauth2token");
//!
//! let options = ClientOptions::default()
//!     .with_credentials_provider(Arc::new(credentials_provider));
//!
//! let client = MqtteaClient::new("broker.example.com", 8883, "my-client", Some(options)).await?;
//! ```

mod oauth2_provider;
mod traits;

pub use oauth2_provider::{OAuth2Config, OAuth2TokenProvider};
pub use traits::{CredentialsProvider, StaticCredentials, TokenCredentialsProvider, TokenProvider};
