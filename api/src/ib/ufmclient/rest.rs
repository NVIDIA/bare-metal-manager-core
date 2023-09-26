/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::time::Duration;

use hyper::client::HttpConnector;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::{Body, Client, Method, Uri};
use hyper_rustls::HttpsConnector;
use hyper_timeout::TimeoutConnector;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RestError {
    #[error("{0}")]
    Internal(String),
    #[error("'{0}' not found")]
    NotFound(String),
    #[error("failed to auth '{0}'")]
    AuthFailure(String),
    #[error("invalid configuration '{0}'")]
    InvalidConfig(String),
}

impl From<hyper::Error> for RestError {
    fn from(value: hyper::Error) -> Self {
        if value.is_user() {
            return RestError::AuthFailure(value.message().to_string());
        }

        RestError::Internal(value.message().to_string())
    }
}

const REST_TIME_OUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub enum RestScheme {
    Http,
    Https,
}

impl From<String> for RestScheme {
    fn from(value: String) -> Self {
        match value.to_uppercase().as_str() {
            "HTTP" => RestScheme::Http,
            "HTTPS" => RestScheme::Https,
            _ => RestScheme::Http,
        }
    }
}

impl Display for RestScheme {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RestScheme::Http => write!(f, "http"),
            RestScheme::Https => write!(f, "https"),
        }
    }
}

pub struct RestClientConfig {
    pub address: String,
    pub port: Option<u16>,
    pub scheme: RestScheme,
    pub auth_info: String,
    pub base_path: String,
}

pub struct RestClient {
    base_url: String,
    auth_info: String,
    scheme: RestScheme,
    http_client: hyper::Client<TimeoutConnector<HttpConnector>>,
    https_client: hyper::Client<TimeoutConnector<HttpsConnector<HttpConnector>>>,
}

impl RestClient {
    pub fn new(conf: &RestClientConfig) -> Result<RestClient, RestError> {
        let auth_info = format!("Basic {}", conf.auth_info.clone().trim());

        let base_url = match &conf.port {
            None => format!(
                "{}://{}/{}",
                conf.scheme,
                conf.address,
                conf.base_path.trim_matches('/')
            ),
            Some(p) => format!(
                "{}://{}:{}/{}",
                conf.scheme,
                conf.address,
                p,
                conf.base_path.trim_matches('/')
            ),
        };

        let _ = base_url
            .parse::<Uri>()
            .map_err(|_| RestError::InvalidConfig("invalid rest address".to_string()))?;

        let mut http_connector = TimeoutConnector::new(HttpConnector::new());
        http_connector.set_connect_timeout(Some(REST_TIME_OUT));
        http_connector.set_read_timeout(Some(REST_TIME_OUT));
        http_connector.set_write_timeout(Some(REST_TIME_OUT));

        let mut https_connector = TimeoutConnector::new(
            hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .https_only()
                .enable_http1()
                .build(),
        );
        https_connector.set_connect_timeout(Some(REST_TIME_OUT));
        https_connector.set_read_timeout(Some(REST_TIME_OUT));
        https_connector.set_write_timeout(Some(REST_TIME_OUT));

        Ok(Self {
            base_url,
            auth_info,
            scheme: conf.scheme.clone(),
            http_client: Client::builder().build::<_, hyper::Body>(http_connector),
            https_client: Client::builder().build::<_, hyper::Body>(https_connector),
        })
    }

    pub async fn get<'a, T: serde::de::DeserializeOwned>(
        &'a self,
        path: &'a str,
    ) -> Result<T, RestError> {
        let resp = self.execute_request(Method::GET, path, None).await?;
        if resp.eq("{}") {
            return Err(RestError::NotFound(path.to_string()));
        }

        let data = serde_json::from_str(&resp)
            .map_err(|_| RestError::InvalidConfig("invalid response".to_string()))?;

        Ok(data)
    }

    pub async fn list<'a, T: serde::de::DeserializeOwned>(
        &'a self,
        path: &'a str,
    ) -> Result<T, RestError> {
        let resp = self.execute_request(Method::GET, path, None).await?;
        let data = serde_json::from_str(&resp)
            .map_err(|_| RestError::InvalidConfig("invalid response".to_string()))?;

        Ok(data)
    }
    pub async fn post(&self, path: &str, data: String) -> Result<(), RestError> {
        self.execute_request(Method::POST, path, Some(data)).await?;

        Ok(())
    }

    pub async fn delete(&self, path: &str) -> Result<(), RestError> {
        self.execute_request(Method::DELETE, path, None).await?;

        Ok(())
    }

    async fn execute_request(
        &self,
        method: Method,
        path: &str,
        data: Option<String>,
    ) -> Result<String, RestError> {
        let url = format!("{}/{}", self.base_url, path.trim_matches('/'));
        let uri = url
            .parse::<Uri>()
            .map_err(|_| RestError::InvalidConfig("invalid path".to_string()))?;

        let body = data.unwrap_or(String::new());

        let req = hyper::Request::builder()
            .method(method)
            .uri(uri)
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, self.auth_info.to_string())
            .body(Body::from(body))
            .map_err(|_| RestError::InvalidConfig("invalid rest request".to_string()))?;

        let body = match &self.scheme {
            RestScheme::Http => self.http_client.request(req).await?,
            RestScheme::Https => self.https_client.request(req).await?,
        };

        let chunk = hyper::body::to_bytes(body.into_body()).await?;
        let data = String::from_utf8(chunk.to_vec()).unwrap();

        Ok(data)
    }
}
