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
// tests/traits.rs
// Unit tests for trait implementations and message handling functionality,
// including RawMessageType, MqttRecipient, and MessageHandler traits.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use mqttea::client::ClientOptions;
use mqttea::registry::traits::RawRegistration;
use mqttea::traits::{MessageHandler, MqttRecipient, RawMessageType};
use mqttea::{MqtteaClient, QoS};
use tokio::sync::Mutex;

// Test message types implementing RawMessageType
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct CatMessage {
    name: String,
    mood: String,
    payload: Vec<u8>,
}

impl RawMessageType for CatMessage {
    fn to_bytes(&self) -> Vec<u8> {
        format!(
            "{}:{}:{}",
            self.name,
            self.mood,
            String::from_utf8_lossy(&self.payload)
        )
        .into_bytes()
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        let content = String::from_utf8_lossy(&bytes);
        let parts: Vec<&str> = content.splitn(3, ':').collect();
        if parts.len() >= 3 {
            Self {
                name: parts[0].to_string(),
                mood: parts[1].to_string(),
                payload: parts[2].as_bytes().to_vec(),
            }
        } else {
            Self {
                name: "unknown".to_string(),
                mood: "unknown".to_string(),
                payload: bytes,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct DogMessage {
    breed: String,
    energy_level: u8,
    good_boy: bool,
}

impl RawMessageType for DogMessage {
    fn to_bytes(&self) -> Vec<u8> {
        format!(
            "{}:{}:{}",
            self.breed,
            self.energy_level,
            if self.good_boy { "1" } else { "0" }
        )
        .into_bytes()
    }

    fn from_bytes(bytes: Vec<u8>) -> Self {
        let content = String::from_utf8_lossy(&bytes);
        let parts: Vec<&str> = content.splitn(3, ':').collect();
        if parts.len() >= 3 {
            Self {
                breed: parts[0].to_string(),
                energy_level: parts[1].parse().unwrap_or(5),
                good_boy: parts[2] == "1",
            }
        } else {
            Self {
                breed: "unknown".to_string(),
                energy_level: 5,
                good_boy: true,
            }
        }
    }
}

// Test recipient types implementing MqttRecipient
#[derive(Debug, Clone)]
struct PetDeviceCollar {
    pet_name: String,
    device_type: String,
    priority: bool,
}

impl MqttRecipient for PetDeviceCollar {
    fn to_mqtt_topic(&self) -> String {
        if self.priority {
            format!("/priority/pets/{}/{}", self.pet_name, self.device_type)
        } else {
            format!("/pets/{}/{}", self.pet_name, self.device_type)
        }
    }
}

#[derive(Debug, Clone)]
struct VeterinaryClinic {
    clinic_id: String,
    department: String,
}

impl MqttRecipient for VeterinaryClinic {
    fn to_mqtt_topic(&self) -> String {
        format!("/vet/clinics/{}/{}", self.clinic_id, self.department)
    }
}

// Message handlers for testing
struct CatMessageHandler {
    received_messages: Arc<Mutex<Vec<(CatMessage, String)>>>,
    call_count: Arc<AtomicUsize>,
}

impl CatMessageHandler {
    fn new() -> Self {
        Self {
            received_messages: Arc::new(Mutex::new(Vec::new())),
            call_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn get_messages(&self) -> Vec<(CatMessage, String)> {
        self.received_messages.lock().await.clone()
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl MessageHandler<CatMessage> for CatMessageHandler {
    async fn handle(&self, _client: Arc<MqtteaClient>, message: CatMessage, topic: String) {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        let mut messages = self.received_messages.lock().await;
        messages.push((message, topic));
    }
}

async fn create_test_client() -> Arc<MqtteaClient> {
    MqtteaClient::new(
        "localhost",
        1883,
        "test-client",
        Some(ClientOptions::default().with_qos(QoS::AtMostOnce)),
    )
    .await
    .unwrap()
}

// Tests for RawMessageType implementations
#[test]
fn test_cat_message_serialization() {
    let cat_msg = CatMessage {
        name: "Whiskers".to_string(),
        mood: "playful".to_string(),
        payload: b"meow meow".to_vec(),
    };

    let bytes = cat_msg.to_bytes();
    let restored = CatMessage::from_bytes(bytes);

    assert_eq!(cat_msg, restored, "Cat message should roundtrip correctly");
}

#[test]
fn test_dog_message_serialization() {
    let dog_msg = DogMessage {
        breed: "Golden Retriever".to_string(),
        energy_level: 9,
        good_boy: true,
    };

    let bytes = dog_msg.to_bytes();
    let restored = DogMessage::from_bytes(bytes);

    assert_eq!(dog_msg, restored, "Dog message should roundtrip correctly");
}

#[test]
fn test_cat_message_with_special_characters() {
    let cat_msg = CatMessage {
        name: "Mr. Whiskers-O'Malley".to_string(),
        mood: "very-excited".to_string(), // Use dash instead of colon to avoid parsing issues
        payload: b"special-chars-in-payload".to_vec(), // Use dashes instead of colons
    };

    let bytes = cat_msg.to_bytes();
    let restored = CatMessage::from_bytes(bytes);

    assert_eq!(cat_msg.name, restored.name, "Name should be preserved");
    assert_eq!(cat_msg.mood, restored.mood, "Mood should be preserved");
    assert_eq!(
        cat_msg.payload, restored.payload,
        "Payload should be preserved"
    );
}

// Tests for MqttRecipient implementations
#[test]
fn test_pet_device_collar_topic_generation() {
    let collar = PetDeviceCollar {
        pet_name: "Luna".to_string(),
        device_type: "collar".to_string(),
        priority: false,
    };

    let topic = collar.to_mqtt_topic();
    assert_eq!(
        topic, "/pets/Luna/collar",
        "Regular pet device topic should be correct"
    );
}

#[test]
fn test_priority_pet_device_topic_generation() {
    let emergency_collar = PetDeviceCollar {
        pet_name: "Max".to_string(),
        device_type: "emergency-beacon".to_string(),
        priority: true,
    };

    let topic = emergency_collar.to_mqtt_topic();
    assert_eq!(
        topic, "/priority/pets/Max/emergency-beacon",
        "Priority pet device topic should be correct"
    );
}

#[test]
fn test_veterinary_clinic_topic_generation() {
    let clinic = VeterinaryClinic {
        clinic_id: "downtown-vet".to_string(),
        department: "emergency".to_string(),
    };

    let topic = clinic.to_mqtt_topic();
    assert_eq!(
        topic, "/vet/clinics/downtown-vet/emergency",
        "Veterinary clinic topic should be correct"
    );
}

// Tests for MessageHandler implementations
#[tokio::test]
async fn test_cat_message_handler() {
    let test_client = create_test_client().await;

    // Register the message type first
    test_client
        .register_raw_message::<CatMessage>("cats/.*")
        .await
        .unwrap();

    let handler = CatMessageHandler::new();

    let cat_msg = CatMessage {
        name: "Simba".to_string(),
        mood: "sleepy".to_string(),
        payload: b"zzz".to_vec(),
    };

    // Test handling a message with Arc<MqtteaClient>
    handler
        .handle(
            test_client,
            cat_msg.clone(),
            "/cats/luna/status".to_string(),
        )
        .await;

    assert_eq!(handler.call_count(), 1, "Handler should be called once");

    let messages = handler.get_messages().await;
    assert_eq!(messages.len(), 1, "Should have one received message");
    assert_eq!(messages[0].0, cat_msg, "Message should match");
    assert_eq!(messages[0].1, "/cats/luna/status", "Topic should match");
}

// Test error resilience
#[tokio::test]
async fn test_malformed_message_handling() {
    // Test how RawMessageType handles malformed data
    let malformed_data = b"incomplete".to_vec();

    let cat_from_malformed = CatMessage::from_bytes(malformed_data.clone());
    assert_eq!(
        cat_from_malformed.name, "unknown",
        "Should handle malformed data gracefully"
    );
    assert_eq!(
        cat_from_malformed.mood, "unknown",
        "Should use default values"
    );
    assert_eq!(
        cat_from_malformed.payload, malformed_data,
        "Should preserve original payload"
    );

    let dog_from_malformed = DogMessage::from_bytes(malformed_data);
    assert_eq!(
        dog_from_malformed.breed, "unknown",
        "Should handle malformed data gracefully"
    );
    assert_eq!(
        dog_from_malformed.energy_level, 5,
        "Should use default energy level"
    );
    assert!(
        dog_from_malformed.good_boy,
        "Should assume dogs are good boys by default"
    );
}
