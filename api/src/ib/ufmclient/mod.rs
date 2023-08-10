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

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use self::rest::{RestClient, RestClientConfig, RestError, RestScheme};

mod rest;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PartitionQoS {
    // Default 2k; one of 2k or 4k; the MTU of the services.
    pub mtu_limit: u16,
    // Default is None, value can be range from 0-15
    pub service_level: u8,
    // Default is None, can be one of the following: 2.5, 10, 30, 5, 20, 40, 60, 80, 120, 14, 56, 112, 168, 25, 100, 200, or 300
    pub rate_limit: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PortMembership {
    Limited,
    Full,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PortConfig {
    /// The GUID of Port.
    pub guid: String,
    /// Default false; store the PKey at index 0 of the PKey table of the GUID.
    pub index0: bool,
    /// Default is full:
    ///   "full"    - members with full membership can communicate with all hosts (members) within the network/partition
    ///   "limited" - members with limited membership cannot communicate with other members with limited membership.
    ///               However, communication is allowed between every other combination of membership types.
    pub membership: PortMembership,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PartitionKey(i32);

#[derive(Serialize, Deserialize, Debug)]
pub struct Partition {
    /// The name of Partition.
    pub name: String,
    /// The pkey of Partition.
    pub pkey: PartitionKey,
    /// Default false
    pub ipoib: bool,
    /// The QoS of Partition.
    pub qos: PartitionQoS,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Port {
    pub guid: String,
    pub name: String,
    #[serde(rename = "systemID")]
    pub system_id: String,
    pub lid: i32,
    pub dname: String,
    pub system_name: String,
    pub physical_state: String,
    pub logical_state: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Pkey {
    pkey: String,
    ip_over_ib: bool,
    membership: PortMembership,
    index0: bool,
    guids: Vec<String>,
}

#[derive(Default)]
pub struct Filter {
    pub guids: Option<Vec<String>>,
    pub pkey: Option<PartitionKey>,
}

impl Filter {
    fn valid(&self, p: &Port) -> bool {
        // Check GUID filter
        if let Some(guids) = &self.guids {
            let mut found = false;
            for id in guids {
                if p.guid == *id {
                    found = true;
                    break;
                }
            }

            if !found {
                return false;
            }
        }

        // All filters are passed, return true.
        true
    }
}

impl From<Vec<PortConfig>> for Filter {
    fn from(guids: Vec<PortConfig>) -> Self {
        let mut v = Vec::new();
        for i in &guids {
            v.push(i.guid.to_string());
        }

        Self {
            guids: Some(v),
            pkey: None,
        }
    }
}

impl TryFrom<i32> for PartitionKey {
    type Error = UFMError;

    fn try_from(pkey: i32) -> Result<Self, Self::Error> {
        if pkey != (pkey & 0x7fff) {
            return Err(UFMError::InvalidPKey(pkey.to_string()));
        }

        Ok(PartitionKey(pkey))
    }
}

impl TryFrom<String> for PartitionKey {
    type Error = UFMError;

    fn try_from(pkey: String) -> Result<Self, Self::Error> {
        let p = pkey.trim_start_matches("0x");
        let k = i32::from_str_radix(p, 16);

        match k {
            Ok(v) => Ok(PartitionKey(v)),
            Err(_e) => Err(UFMError::InvalidPKey(pkey.to_string())),
        }
    }
}

impl TryFrom<&String> for PartitionKey {
    type Error = UFMError;

    fn try_from(pkey: &String) -> Result<Self, Self::Error> {
        PartitionKey::try_from(pkey.to_string())
    }
}

impl TryFrom<&str> for PartitionKey {
    type Error = UFMError;

    fn try_from(pkey: &str) -> Result<Self, Self::Error> {
        PartitionKey::try_from(pkey.to_string())
    }
}

impl ToString for PartitionKey {
    fn to_string(&self) -> String {
        format!("0x{:x}", self.0)
    }
}

impl From<PartitionKey> for i32 {
    fn from(v: PartitionKey) -> i32 {
        v.0
    }
}

pub struct Ufm {
    client: RestClient,
}

#[derive(Error, Debug)]
pub enum UFMError {
    #[error("{0}")]
    Internal(String),
    #[error("'{0}' not found")]
    NotFound(String),
    #[error("invalid pkey '{0}'")]
    InvalidPKey(String),
    #[error("invalid configuration '{0}'")]
    InvalidConfig(String),
}

impl From<RestError> for UFMError {
    fn from(e: RestError) -> Self {
        match e {
            RestError::Internal(msg) => UFMError::Internal(msg),
            RestError::NotFound(msg) => UFMError::NotFound(msg),
            RestError::AuthFailure(msg) => UFMError::InvalidConfig(msg),
            RestError::InvalidConfig(msg) => UFMError::InvalidConfig(msg),
        }
    }
}

pub struct UFMConfig {
    pub address: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
}

pub fn connect(conf: UFMConfig) -> Result<Ufm, UFMError> {
    let addr = Url::parse(&conf.address)
        .map_err(|_| UFMError::InvalidConfig("invalid UFM url".to_string()))?;
    let address = addr
        .host_str()
        .ok_or(UFMError::InvalidConfig("invalid UFM host".to_string()))?;

    let (base_path, auth_info) = match &conf.token {
        None => {
            let password = conf
                .password
                .clone()
                .ok_or(UFMError::InvalidConfig("password is empty".to_string()))?;
            let username = conf
                .username
                .clone()
                .ok_or(UFMError::InvalidConfig("username is empty".to_string()))?;

            (
                "/ufmRest".to_string(),
                base64::encode(format!("{}:{}", username, password)),
            )
        }
        Some(t) => ("/ufmRestV3".to_string(), t.to_string()),
    };

    let c = RestClient::new(&RestClientConfig {
        address: address.to_string(),
        port: addr.port(),
        auth_info,
        base_path,
        scheme: RestScheme::from(addr.scheme().to_string()),
    })?;

    Ok(Ufm { client: c })
}

impl Ufm {
    pub async fn bind_ports(&self, p: Partition, ports: Vec<PortConfig>) -> Result<(), UFMError> {
        let path = String::from("/resources/pkeys");

        let mut membership = PortMembership::Full;
        let mut index0 = true;

        let mut guids = Vec::with_capacity(ports.len());
        for pb in ports {
            membership = pb.membership.clone();
            index0 = pb.index0;
            guids.push(pb.guid.to_string());
        }

        let pkey = Pkey {
            pkey: p.pkey.clone().to_string(),
            ip_over_ib: p.ipoib,
            membership,
            index0,
            guids,
        };

        let data = serde_json::to_string(&pkey)
            .map_err(|_| UFMError::InvalidConfig("invalid partition".to_string()))?;

        self.client.post(&path, data).await?;

        Ok(())
    }

    pub async fn unbind_ports(
        &self,
        pkey: PartitionKey,
        guids: Vec<String>,
    ) -> Result<(), UFMError> {
        let path = String::from("/actions/remove_guids_from_pkey");

        #[derive(Serialize, Deserialize, Debug)]
        struct Pkey {
            pkey: String,
            guids: Vec<String>,
        }

        let pkey = Pkey {
            pkey: pkey.clone().to_string(),
            guids,
        };

        let data = serde_json::to_string(&pkey)
            .map_err(|_| UFMError::InvalidConfig("invalid partition".to_string()))?;

        self.client.post(&path, data).await?;

        Ok(())
    }

    pub async fn get_partition(&self, pkey: &str) -> Result<Partition, UFMError> {
        let pkey = PartitionKey::try_from(pkey)?;

        let path = format!("/resources/pkeys/{}?qos_conf=true", pkey.to_string());

        #[derive(Serialize, Deserialize, Debug)]
        struct Pkey {
            partition: String,
            ip_over_ib: bool,
            qos_conf: PartitionQoS,
        }
        let pk: Pkey = self.client.get(&path).await?;

        Ok(Partition {
            name: pk.partition,
            pkey,
            ipoib: pk.ip_over_ib,
            qos: pk.qos_conf,
        })
    }

    pub async fn list_partition(&self) -> Result<Vec<Partition>, UFMError> {
        #[derive(Serialize, Deserialize, Debug)]
        struct Pkey {
            partition: String,
            ip_over_ib: bool,
            qos_conf: PartitionQoS,
        }

        let path = String::from("/resources/pkeys?qos_conf=true");
        let pkey_qos: HashMap<String, Pkey> = self.client.list(&path).await?;

        let mut parts = Vec::new();

        for (k, v) in pkey_qos {
            parts.push(Partition {
                name: v.partition,
                pkey: PartitionKey::try_from(&k)?,
                ipoib: v.ip_over_ib,
                qos: v.qos_conf.clone(),
            });
        }

        Ok(parts)
    }

    pub async fn delete_partition(&self, pkey: &str) -> Result<(), UFMError> {
        let path = format!("/resources/pkeys/{}", pkey);
        self.client.delete(&path).await?;

        Ok(())
    }

    async fn list_partition_ports(&self, pkey: &PartitionKey) -> Result<Vec<String>, UFMError> {
        // get GUIDs from pkey
        #[derive(Serialize, Deserialize, Debug)]
        struct PkeyWithGUIDs {
            pub partition: String,
            pub ip_over_ib: bool,
            pub guids: Vec<PortConfig>,
        }

        let path = format!("resources/pkeys/{}?guids_data=true", pkey.to_string());
        let pkeywithguids: PkeyWithGUIDs = self.client.get(&path).await?;

        let filter = Filter::from(pkeywithguids.guids);

        Ok(filter.guids.unwrap_or(vec![]))
    }

    pub async fn list_port(&self, filter: Option<Filter>) -> Result<Vec<Port>, UFMError> {
        let path = String::from("/resources/ports?sys_type=Computer");
        let ports: Vec<Port> = self.client.list(&path).await?;

        let mut f = filter.unwrap_or(Filter::default());
        if let Some(pkey) = &f.pkey {
            let mut ports = self.list_partition_ports(pkey).await?;
            ports.extend(f.guids.unwrap_or(vec![]));
            f.guids = Some(ports);
        }

        let mut res = Vec::new();
        for port in ports {
            if f.valid(&port) {
                res.push(port);
            }
        }

        Ok(res)
    }

    pub async fn version(&self) -> Result<String, UFMError> {
        #[derive(Serialize, Deserialize, Debug)]
        struct Version {
            ufm_release_version: String,
        }

        let path = String::from("/app/ufm_version");
        let v: Version = self.client.get(&path).await?;

        Ok(v.ufm_release_version)
    }
}
