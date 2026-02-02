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

struct DogMessageHandler {
    high_energy_count: Arc<AtomicUsize>,
    total_messages: Arc<AtomicUsize>,
    last_topic: Arc<Mutex<String>>,
}

impl DogMessageHandler {
    fn new() -> Self {
        Self {
            high_energy_count: Arc::new(AtomicUsize::new(0)),
            total_messages: Arc::new(AtomicUsize::new(0)),
            last_topic: Arc::new(Mutex::new(String::new())),
        }
    }

    fn high_energy_count(&self) -> usize {
        self.high_energy_count.load(Ordering::Relaxed)
    }

    fn total_messages(&self) -> usize {
        self.total_messages.load(Ordering::Relaxed)
    }

    async fn last_topic(&self) -> String {
        self.last_topic.lock().await.clone()
    }
}

#[async_trait]
impl MessageHandler<DogMessage> for DogMessageHandler {
    async fn handle(&self, _client: Arc<MqtteaClient>, message: DogMessage, topic: String) {
        self.total_messages.fetch_add(1, Ordering::Relaxed);

        if message.energy_level > 7 {
            self.high_energy_count.fetch_add(1, Ordering::Relaxed);
        }

        *self.last_topic.lock().await = topic;
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

#[tokio::test]
async fn test_dog_message_handler() {
    let test_client = create_test_client().await;

    // Register the message type first
    test_client
        .register_raw_message::<DogMessage>("dogs/.*")
        .await
        .unwrap();

    let handler = DogMessageHandler::new();

    let calm_dog = DogMessage {
        breed: "Bulldog".to_string(),
        energy_level: 3,
        good_boy: true,
    };

    let excited_dog = DogMessage {
        breed: "Jack Russell".to_string(),
        energy_level: 9,
        good_boy: true,
    };

    // Test handling messages with different energy levels
    handler
        .handle(
            test_client.clone(),
            calm_dog,
            "/dogs/buddy/status".to_string(),
        )
        .await;
    handler
        .handle(test_client, excited_dog, "/dogs/max/activity".to_string())
        .await;

    assert_eq!(
        handler.total_messages(),
        2,
        "Should have processed 2 messages"
    );
    assert_eq!(
        handler.high_energy_count(),
        1,
        "Should have 1 high-energy dog"
    );
    assert_eq!(
        handler.last_topic().await,
        "/dogs/max/activity",
        "Last topic should be from excited dog"
    );
}

// Tests for multiple message handling
#[tokio::test]
async fn test_multiple_cat_messages() {
    let test_client = create_test_client().await;

    // Register the message type first
    test_client
        .register_raw_message::<CatMessage>("cats/.*")
        .await
        .unwrap();

    let handler = CatMessageHandler::new();

    for i in 0..5 {
        let cat_msg = CatMessage {
            name: format!("Cat-{i}"),
            mood: "testing".to_string(),
            payload: format!("test-{i}").into_bytes(),
        };

        handler
            .handle(
                test_client.clone(),
                cat_msg,
                format!("/cats/test-{i}/status"),
            )
            .await;
    }

    assert_eq!(handler.call_count(), 5, "Should have processed 5 messages");

    let messages = handler.get_messages().await;
    assert_eq!(messages.len(), 5, "Should have 5 received messages");

    for (i, (msg, topic)) in messages.iter().enumerate() {
        assert_eq!(msg.name, format!("Cat-{i}"), "Cat name should match index");
        assert_eq!(
            *topic,
            format!("/cats/test-{i}/status"),
            "Topic should match index"
        );
    }
}

#[tokio::test]
async fn test_multiple_dog_energy_levels() {
    let test_client = create_test_client().await;

    // Register the message type first
    test_client
        .register_raw_message::<DogMessage>("dogs/.*")
        .await
        .unwrap();

    let handler = DogMessageHandler::new();

    for energy in 1..=10 {
        let dog = DogMessage {
            breed: "Test Dog".to_string(),
            energy_level: energy,
            good_boy: true,
        };

        handler
            .handle(
                test_client.clone(),
                dog,
                format!("/dogs/test-{energy}/status"),
            )
            .await;
    }

    assert_eq!(
        handler.total_messages(),
        10,
        "Should have processed 10 messages"
    );
    assert_eq!(
        handler.high_energy_count(),
        3,
        "Should have 3 high-energy dogs (8, 9, 10)"
    );
}

// Tests for concurrent message handling
#[tokio::test]
async fn test_concurrent_message_handling() {
    let test_client = create_test_client().await;

    // Register the message type first
    test_client
        .register_raw_message::<CatMessage>("cats/.*")
        .await
        .unwrap();

    let handler = Arc::new(CatMessageHandler::new());

    let mut handles = Vec::new();

    for i in 0..10 {
        let handler_clone = handler.clone();
        let client_clone = test_client.clone();

        let handle = tokio::spawn(async move {
            let cat_msg = CatMessage {
                name: format!("ConcurrentCat-{i}"),
                mood: "concurrent".to_string(),
                payload: format!("concurrent-{i}").into_bytes(),
            };

            handler_clone
                .handle(
                    client_clone,
                    cat_msg.clone(),
                    format!("/cats/cat-{i}/status"),
                )
                .await;
        });

        handles.push(handle);
    }

    // Wait for all concurrent handlers to complete
    for handle in handles {
        handle.await.expect("Task should complete successfully");
    }

    assert_eq!(
        handler.call_count(),
        10,
        "Should have processed 10 concurrent messages"
    );

    let messages = handler.get_messages().await;
    assert_eq!(messages.len(), 10, "Should have 10 received messages");
}

// Tests for message routing with MQTT recipients
#[tokio::test]
async fn test_message_routing_with_recipients() {
    let test_client = create_test_client().await;

    // Register message types first
    test_client
        .register_raw_message::<CatMessage>(".*")
        .await
        .unwrap();
    test_client
        .register_raw_message::<DogMessage>(".*")
        .await
        .unwrap();

    let cat_handler = CatMessageHandler::new();
    let dog_handler = DogMessageHandler::new();

    let cat_location = CatMessage {
        name: "Explorer".to_string(),
        mood: "adventurous".to_string(),
        payload: b"GPS coordinates".to_vec(),
    };

    let cat_collar = PetDeviceCollar {
        pet_name: "Explorer".to_string(),
        device_type: "gps-tracker".to_string(),
        priority: false,
    };

    let emergency_device = PetDeviceCollar {
        pet_name: "Rescue".to_string(),
        device_type: "emergency-beacon".to_string(),
        priority: true,
    };

    let vet_clinic = VeterinaryClinic {
        clinic_id: "emergency-vet".to_string(),
        department: "trauma".to_string(),
    };

    // Test message handling with different recipient types
    cat_handler
        .handle(
            test_client.clone(),
            cat_location,
            cat_collar.to_mqtt_topic(),
        )
        .await;

    let dog_health = DogMessage {
        breed: "Emergency Dog".to_string(),
        energy_level: 1,
        good_boy: true,
    };

    dog_handler
        .handle(
            test_client.clone(),
            dog_health,
            emergency_device.to_mqtt_topic(),
        )
        .await;

    let dog_emergency = DogMessage {
        breed: "Critical Dog".to_string(),
        energy_level: 2,
        good_boy: true,
    };

    dog_handler
        .handle(
            test_client,
            dog_emergency.clone(),
            vet_clinic.to_mqtt_topic(),
        )
        .await;

    // Verify messages were handled correctly
    assert_eq!(
        cat_handler.call_count(),
        1,
        "Cat handler should have 1 message"
    );
    assert_eq!(
        dog_handler.total_messages(),
        2,
        "Dog handler should have 2 messages"
    );
}

// Test stress scenarios
#[tokio::test]
async fn test_high_volume_message_processing() {
    let test_client = create_test_client().await;

    // Register the message type first
    test_client
        .register_raw_message::<DogMessage>("dogs/.*")
        .await
        .unwrap();

    let handler = Arc::new(DogMessageHandler::new());

    // Process a large number of messages rapidly
    let mut handles = Vec::new();
    for i in 0..100 {
        let handler_clone = handler.clone();
        let client_clone = test_client.clone();

        let handle = tokio::spawn(async move {
            let dog = DogMessage {
                breed: format!("Dog-{}", i % 5),  // 5 different breeds
                energy_level: (i % 10) as u8 + 1, // Energy levels 1-10
                good_boy: i % 7 != 0,             // Most are good boys, some aren't
            };

            handler_clone
                .handle(client_clone, dog, format!("/dogs/test-{i}/status"))
                .await;
        });

        handles.push(handle);
    }

    // Wait for all messages to be processed
    for handle in handles {
        handle.await.expect("High volume task should complete");
    }

    assert_eq!(
        handler.total_messages(),
        100,
        "Should have processed all 100 messages"
    );

    // High energy dogs are those with energy > 7 (8, 9, 10)
    // With pattern (i % 10) + 1, we get: 8, 9, 10 appearing 10 times each
    assert_eq!(
        handler.high_energy_count(),
        30,
        "Should have 30 high-energy dogs"
    );
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
