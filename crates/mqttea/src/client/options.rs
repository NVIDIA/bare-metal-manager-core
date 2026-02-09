/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// src/client/options.rs
// Configuration options for the Mqttea client.
use rumqttc::QoS;
use tokio::time::Duration;

use crate::registry::types::PublishOptions;

// ClientOptions are optional parameters that can be
// passed to the client, all of which are supposed
// to have default fallbacks.
//
// TODO(chet): This might be worthy of a ::new()
// or ::default() or something, even though
// passing None to the client just gets us
// const defaults anyway. Just trying to be flexible!
#[derive(Clone, Debug, Default)]
pub struct ClientOptions {
    // keep_alive sets the keepalive to use for MQTT broker connections.
    // Defaults to DEFAULT_KEEP_ALIVE.
    pub keep_alive: Option<std::time::Duration>,
    // message_channel_capacity is the number of *messages* the underlying
    // async client queue should buffer before no longer reading additional
    // bytes from the wire.
    // Defaults to DEFAULT_MESSAGE_CHANNEL_CAPACITY.
    pub message_channel_capacity: Option<usize>,
    // publish_options is used when no explicit PublishOptions are provided
    // for a given message type or topic pattern. If this is None, then
    // the default consts are used as fallback.
    pub publish_options: Option<PublishOptions>,
    // client_queue_size sets a limit to the number of messages that
    // can be buffered in our local client queue (between our event
    // loop and message processing tasks) before dropping.
    // Defaults to DEFAULT_CLIENT_QUEUE_SIZE.
    pub client_queue_size: Option<usize>,
    // warn_on_unmatched_topic will tell the client to log warnings
    // any time it encounters a topic pattern without a handler match.
    // Defaults to TRUE.
    pub warn_on_unmatched_topic: Option<bool>,
    // credentials are optional username/password credentials
    // that can be provided to the MQTT server for authnz. This
    // can be used with or without a tls_config.
    pub credentials: Option<ClientCredentials>,
    // tls_config is an optional ClientTlsConfig to provide
    // for using TLS, and optionally, mTLS. This can be used
    // with or without credentials.
    pub tls_config: Option<ClientTlsConfig>,
    // max_concurrency is the maximum number of messages that can be
    // processed concurrently. If unset, defaults to 1, which is
    // effectively sequential processing.
    pub max_concurrency: Option<usize>,
}

impl ClientOptions {
    // Builder methods that consume and return Self
    pub fn with_keep_alive(mut self, keep_alive: Duration) -> Self {
        self.keep_alive = Some(keep_alive);
        self
    }

    pub fn with_message_channel_capacity(mut self, capacity: usize) -> Self {
        self.message_channel_capacity = Some(capacity);
        self
    }

    pub fn with_qos(mut self, qos: QoS) -> Self {
        // Initialize publish_options if None, then set qos
        let mut pub_opts = self.publish_options.unwrap_or_default();
        pub_opts.qos = Some(qos);
        self.publish_options = Some(pub_opts);
        self
    }

    pub fn with_retain(mut self, retain: bool) -> Self {
        let mut pub_opts = self.publish_options.unwrap_or_default();
        pub_opts.retain = Some(retain);
        self.publish_options = Some(pub_opts);
        self
    }

    pub fn with_publish_options(mut self, publish_options: PublishOptions) -> Self {
        self.publish_options = Some(publish_options);
        self
    }

    pub fn with_max_concurrency(mut self, max_concurrency: usize) -> Self {
        self.max_concurrency = Some(max_concurrency);
        self
    }
}

// ClientCredentials are used for providing a username
// and password to the MQTT server.
#[derive(Clone, Debug)]
pub struct ClientCredentials {
    pub username: String,
    pub password: String,
}

// ClientTlsConfig is config for using TLS (and optionally
// mTLS) with the MQTT server.
#[derive(Clone, Debug)]
pub struct ClientTlsConfig {
    // ca_certificate is PEM bytes for a CA certificate (or
    // CA certificate bundle); it is intended these were
    // probably loaded from a file, but could have also
    // been provided over the wire.
    pub ca_certificate: Vec<u8>,
    // client_identity is an optional client certificate
    // and private key to do mTLS with the MQTT server.
    pub client_identity: Option<ClientTlsIdentity>,
}

// ClientTlsIdentity is config to negotiate an mTLS
// handshake with the MQTT server.
#[derive(Clone, Debug)]
pub struct ClientTlsIdentity {
    // certificate is PEM bytes for a client certificate.
    // It is intended these were probably loaded from a
    // file, but could have also been provided over the
    // wire or generated ephemerally.
    pub certificate: Vec<u8>,
    // private_key is PEM bytes for the matching key.
    // It is intended these were probably loaded from a
    // file, but could have also been provided over the
    // wire or generated ephemerally.
    pub private_key: Vec<u8>,
}
