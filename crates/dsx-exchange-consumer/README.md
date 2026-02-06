# carbide-dsx-exchange-consumer

Microservice that consumes BMS leak detection events from the Cronus MQTT event bus and updates rack-level health overrides in the Carbide API.

## Overview

This service bridges the DSX Exchange Event Bus with Carbide's health reporting system. When leak detection events are published by the BMS, this consumer:

1. Receives metadata and value messages from MQTT topics
2. Correlates values with their metadata using point paths
3. Detects leak alerts (value = 1) and clears (value = 0)
4. Updates rack health overrides via the Carbide API

## Supported Leak Types

| Point Type | Probe ID | Description |
|------------|----------|-------------|
| `LeakDetectRack` | `BmsLeakDetectRack` | Rack-level leak detection |
| `LeakSensorFaultRack` | `BmsLeakSensorFaultRack` | Leak sensor fault |
| `LeakDetectRackTray` | `BmsLeakDetectRackTray` | Rack tray leak detection |

## MQTT Topics

- **Metadata**: `cronus/v1/{pointPath}/Metadata`
- **Value**: `cronus/v1/{pointPath}/Value`

The `pointPath` is vendor-defined and may contain multiple `/` segments.

## Configuration

Configuration is loaded from TOML files and environment variables. See `example/config.example.toml`.

### Environment Variables

All config options can be set via environment variables with prefix `CARBIDE_DSX_CONSUMER__` and `__` as separator:

```bash
CARBIDE_DSX_CONSUMER__MQTT__ENDPOINT=mqtt.forge
CARBIDE_DSX_CONSUMER__MQTT__PORT=1884
CARBIDE_DSX_CONSUMER__CACHE__METADATA_TTL=1h
```

### Key Options

| Option | Default | Description |
|--------|---------|-------------|
| `mqtt.endpoint` | `mqtt.forge` | MQTT broker hostname |
| `mqtt.port` | `1884` | MQTT broker port |
| `mqtt.topic_prefix` | `cronus/v1` | Topic prefix for subscriptions |
| `mqtt.queue_capacity` | `1024` | Internal message queue size |
| `cache.metadata_ttl` | `1h` | TTL for metadata cache |
| `cache.value_state_ttl` | `1h` | TTL for deduplication cache |

## Metrics

Exposed on the configured metrics endpoint (default `:9009`):

| Metric | Type | Description |
|--------|------|-------------|
| `carbide_dsx_exchange_consumer_messages_received_total` | Counter | Total MQTT messages received |
| `carbide_dsx_exchange_consumer_messages_processed_total` | Counter | Messages successfully processed |
| `carbide_dsx_exchange_consumer_messages_dropped_total` | Counter | Messages dropped (queue overflow) |
| `carbide_dsx_exchange_consumer_alerts_detected_total` | Counter | Leak alerts detected (by point_type) |
| `carbide_dsx_exchange_consumer_dedup_skipped_total` | Counter | Messages skipped (deduplication) |
| `carbide_dsx_exchange_consumer_metadata_cache_size` | Gauge | Metadata cache entry count |
| `carbide_dsx_exchange_consumer_value_state_cache_size` | Gauge | Value state cache entry count |

## Running

```bash
# With config file
cargo run -p carbide-dsx-exchange-consumer -- --config config.toml

# With environment variables only
CARBIDE_DSX_CONSUMER__MQTT__ENDPOINT=localhost cargo run -p carbide-dsx-exchange-consumer
```

## Testing

```bash
cargo test -p carbide-dsx-exchange-consumer
```

## Disabling the API Client

For testing without a Carbide API connection, set:

```toml
[carbide_api]
enabled = false
```

This logs health updates to the console instead of calling the API.
