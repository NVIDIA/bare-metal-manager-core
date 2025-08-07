# mqttea

A high-performance, type-safe MQTT client library with built-in support for protobuf, JSON, YAML, and custom serialization formats for Rust.

mqttea provides a clean, async-first API for MQTT communication with automatic message serialization across multiple formats, client-scoped message registries, and comprehensive connection management. Built on top of rumqttc, it offers production-ready reliability with an ergonomic developer experience that lets you focus on your application logic, not message handling.

## Features

• **Decoupled message processing** - Fast MQTT message ingestion with separate processing queue prevents handler blocking
• **Multiple serialization formats** - Built-in support for protobuf, JSON, YAML, and raw bytes with extensible custom format support
• **Type-safe message handling** - Automatic serialization/deserialization with compile-time type safety
• **Client-scoped message registries** - Multiple clients can register different message types independently
• **Async-first design** - Built on tokio with non-blocking operations throughout
• **Comprehensive statistics** - Built-in tracking for queue depth, message throughput, and publish metrics
• **Flexible QoS support** - Per-message quality of service configuration
• **Connection resilience** - Automatic reconnection and connection state management
• **Zero-copy message handling** - Efficient encoding/decoding with minimal allocations
• **Production monitoring** - Structured logging with tracing integration

## Production Ready

mqttea is designed for production workloads with:

- **Lock-free statistics tracking** using atomic operations for high-throughput scenarios
- **Memory-efficient message processing** with Arc-based sharing and zero-copy operations
- **Robust error handling** with comprehensive error types and recovery mechanisms
- **Thread-safe client sharing** allowing safe concurrent access across async tasks
- **Configurable connection parameters** for tuning to specific network conditions
- **Extensive test coverage** with unit tests for all core functionality

## Architecture & Performance

### Decoupled Message Processing

mqttea uses a sophisticated two-stage architecture that ensures your MQTT broker connection stays responsive even under heavy message processing loads:

```
MQTT Broker → Fast Ingestion → Message Queue → Background Processing → Your Handlers
```

**Stage 1: Fast Message Ingestion**
- Messages are immediately read from the MQTT broker and queued
- No blocking on message processing or handler execution
- Maintains low-latency broker acknowledgments
- Prevents message loss during processing spikes

**Stage 2: Background Message Processing**
- Separate async task processes queued messages
- Messages are deserialized and routed to appropriate handlers
- Handler execution doesn't block new message ingestion
- Failed messages don't affect broker connectivity

### Real-Time Queue Monitoring

Track your message processing pipeline with built-in statistics:

```rust
// Monitor message flow
let queue_stats = client.queue_stats();
println!("Queue: {} pending, {} processed, {} bytes queued",
         queue_stats.pending_count,
         queue_stats.processed_count,
         queue_stats.pending_bytes);

let publish_stats = client.publish_stats();
println!("Published: {} messages, {} bytes sent",
         publish_stats.message_count,
         publish_stats.total_bytes);

// Graceful shutdown - wait for queue to drain
client.wait_for_queue_empty().await;
```

This architecture ensures that even if your message handlers are slow or occasionally fail, your MQTT connection remains healthy and continues ingesting messages at full speed.

## Supported Serialization Formats

mqttea supports multiple serialization formats out of the box, plus the ability to add your own custom formats:

### JSON (with serde)
```rust
#[derive(Serialize, Deserialize)]
struct CatStatus {
    name: String,
    mood: String,
}

client.register_json_message::<CatStatus>("status").await?;
```

### Protobuf (with prost)
```rust
#[derive(prost::Message)]
struct SensorReading {
    #[prost(string, tag = "1")]
    device_id: String,
    #[prost(float, tag = "2")]
    temperature: f32,
}

client.register_protobuf_message::<SensorReading>("sensor").await?;
```

### YAML (with serde)
```rust
#[derive(Serialize, Deserialize)]
struct Configuration {
    host: String,
    port: u16,
    enabled: bool,
}

client.register_yaml_message::<Configuration>("config").await?;
```

### Raw Bytes
```rust
struct LogMessage {
    timestamp: u64,
    data: Vec<u8>,
}

impl RawMessageType for LogMessage {
    fn from_raw_parts(topic: String, payload: Vec<u8>) -> Result<Self, MqtteaClientError> {
        Ok(LogMessage {
            timestamp: chrono::Utc::now().timestamp() as u64,
            data: payload,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

client.register_raw_message::<LogMessage>("logs").await?;
```

### Custom Formats
You can easily add support for your own serialization formats by implementing the serialization traits and registering custom handlers. See the documentation for extending mqttea with formats like MessagePack, CBOR, or your own binary protocols.

## Quick Start

### Basic Message Publishing

```rust
use mqttea::MqtteaClient;
use rumqttc::QoS;
use serde::{Deserialize, Serialize};

// Define your own JSON message type - let's track our pets!
#[derive(Serialize, Deserialize, Debug)]
struct CatStatus {
    name: String,
    mood: String,           // "sleepy", "playful", "hungry", "plotting world domination"
    location: String,       // "windowsill", "cardboard box", "your keyboard"
    timestamp: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new MQTT client
    let mut client = MqtteaClient::new(
        "localhost",
        1883,
        "pet-tracker",
        "/pets",
        QoS::AtLeastOnce
    ).await?;

    // Register your custom JSON message type
    client.register_json_message::<CatStatus>("status").await?;

    // Send a message about Whiskers
    let message = CatStatus {
        name: "Whiskers".to_string(),
        mood: "plotting world domination".to_string(),
        location: "cardboard box fortress".to_string(),
        timestamp: chrono::Utc::now().timestamp() as u64,
    };

    client.send_message("/pets/whiskers/status", &message).await?;
    Ok(())
}
```

### Message Subscription and Handling

```rust
use mqttea::MqtteaClient;
use rumqttc::QoS;
use serde::{Deserialize, Serialize};

// Define your own JSON message types for pet monitoring
#[derive(Serialize, Deserialize, Debug)]
struct DogActivity {
    name: String,
    activity: String,       // "napping", "playing fetch", "begging for treats", "barking at mailman"
    energy_level: u8,       // 1-10 scale
    last_treat_time: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct HamsterUpdate {
    name: String,
    wheel_distance: f32,    // miles run on wheel today
    cheek_fullness: u8,     // 1-10 scale of how stuffed their cheeks are
    is_building_fort: bool, // are they rearranging their bedding?
    timestamp: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = MqtteaClient::new(
        "localhost",
        1883,
        "pet-monitor",
        "/pets",
        QoS::AtLeastOnce
    ).await?;

    // Register your custom JSON message types
    client.register_json_message::<DogActivity>("activity").await?;
    client.register_json_message::<HamsterUpdate>("update").await?;

    // Subscribe to pet updates
    client.subscribe("/pets/+/activity").await?;
    client.subscribe("/pets/+/update").await?;

    // Start message processing
    let mut message_stream = client.start_message_processing().await?;

    while let Some(result) = message_stream.recv().await {
        match result {
            Ok((topic, type_name, data)) => {
                match type_name.as_str() {
                    "DogActivity" => {
                        let activity: DogActivity = client.deserialize_any(&data)?;
                        println!("{} is {} (energy: {}/10, last treat: {} mins ago)",
                                activity.name, activity.activity, activity.energy_level,
                                (chrono::Utc::now().timestamp() as u64 - activity.last_treat_time) / 60);
                    }
                    "HamsterUpdate" => {
                        let update: HamsterUpdate = client.deserialize_any(&data)?;
                        println!("{} ran {:.1} miles today! Cheeks: {}/10 full, Fort building: {}",
                                update.name, update.wheel_distance, update.cheek_fullness,
                                if update.is_building_fort { "YES!" } else { "nope" });
                    }
                    _ => println!("Unknown pet message type: {}", type_name),
                }
            }
            Err(e) => eprintln!("Pet monitoring error: {}", e),
        }
    }

    Ok(())
}
```

### Advanced Usage with Statistics

```rust
use mqttea::MqtteaClient;
use rumqttc::QoS;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// Define your own JSON message type for pet health monitoring
#[derive(Serialize, Deserialize, Debug)]
struct RabbitHealthCheck {
    name: String,
    weight_grams: u32,
    hay_consumed_grams: u32,
    pellets_eaten: u8,
    binky_count: u8,        // number of happy jumps today!
    litter_box_visits: u8,
    vet_checkup_due: bool,
    timestamp: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = MqtteaClient::new(
        "localhost",
        1883,
        "rabbit-health-monitor",
        "/pets",
        QoS::AtLeastOnce
    ).await?;

    // Register your custom JSON message type
    client.register_json_message::<RabbitHealthCheck>("health").await?;

    // Send health data for multiple rabbits
    let rabbit_names = ["Cocoa", "Marshmallow", "Pepper", "Cinnamon", "Nutmeg"];

    for i in 0..100 {
        let rabbit_name = rabbit_names[i % rabbit_names.len()];
        let health_check = RabbitHealthCheck {
            name: rabbit_name.to_string(),
            weight_grams: 1200 + (i % 200) as u32,  // healthy weight variation
            hay_consumed_grams: 80 + (i % 40) as u32,
            pellets_eaten: 15 + (i % 5) as u8,
            binky_count: (i % 8) as u8,             // some days are more exciting!
            litter_box_visits: 8 + (i % 4) as u8,
            vet_checkup_due: i % 30 == 0,           // checkup every 30 reports
            timestamp: chrono::Utc::now().timestamp() as u64,
        };

        client.send_message(&format!("/pets/{}/health", rabbit_name.to_lowercase()), &health_check).await?;
    }

    // Check statistics
    let queue_stats = client.queue_stats();
    let publish_stats = client.publish_stats();

    println!("Rabbit health monitoring stats:");
    println!("Queue: {} pending, {} processed",
             queue_stats.pending_count,
             queue_stats.processed_count);
    println!("Published: {} health reports, {} bytes of bunny data!",
             publish_stats.message_count,
             publish_stats.total_bytes);

    Ok(())
}
```
