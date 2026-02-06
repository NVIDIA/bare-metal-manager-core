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

// tests/stats.rs
// Unit tests for statistics tracking functionality including queue statistics
// for received messages and publish statistics for sent messages.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use mqttea::stats::{PublishStatsTracker, QueueStatsTracker};

// Tests for QueueStatsTracker creation and initial state
#[test]
fn test_queue_stats_tracker_creation() {
    let tracker = QueueStatsTracker::new();
    let stats = tracker.to_stats();

    assert_eq!(stats.pending_messages, 0);
    assert_eq!(stats.pending_bytes, 0);
    assert_eq!(stats.total_processed, 0);
    assert_eq!(stats.total_failed, 0);
    assert_eq!(stats.total_bytes_processed, 0);
    assert!(tracker.is_empty());
}

#[test]
fn test_queue_stats_increment_pending() {
    let tracker = QueueStatsTracker::new();

    // Add some pending messages
    tracker.increment_pending(100); // First message: 100 bytes
    tracker.increment_pending(250); // Second message: 250 bytes
    tracker.increment_pending(75); // Third message: 75 bytes

    let stats = tracker.to_stats();
    assert_eq!(stats.pending_messages, 3);
    assert_eq!(stats.pending_bytes, 425);
    assert_eq!(stats.total_processed, 0);
    assert_eq!(stats.total_failed, 0);
    assert!(!tracker.is_empty());
}

#[test]
fn test_queue_stats_process_messages() {
    let tracker = QueueStatsTracker::new();

    // Add pending messages
    tracker.increment_pending(150);
    tracker.increment_pending(200);

    // Process one message successfully
    tracker.decrement_pending_increment_processed(150);

    let stats = tracker.to_stats();
    assert_eq!(stats.pending_messages, 1);
    assert_eq!(stats.pending_bytes, 200);
    assert_eq!(stats.total_processed, 1);
    assert_eq!(stats.total_bytes_processed, 150);
    assert_eq!(stats.total_failed, 0);
}

#[test]
fn test_queue_stats_fail_messages() {
    let tracker = QueueStatsTracker::new();

    // Add pending messages
    tracker.increment_pending(300);
    tracker.increment_pending(400);

    // Fail one message
    tracker.decrement_pending_increment_failed(300);

    let stats = tracker.to_stats();
    assert_eq!(stats.pending_messages, 1);
    assert_eq!(stats.pending_bytes, 400);
    assert_eq!(stats.total_processed, 0);
    assert_eq!(stats.total_failed, 1);
    assert_eq!(stats.total_bytes_processed, 0);
}

#[test]
fn test_queue_stats_mixed_operations() {
    let tracker = QueueStatsTracker::new();

    // Simulate realistic message processing flow
    tracker.increment_pending(100); // Cat photo received
    tracker.increment_pending(250); // Dog video received
    tracker.increment_pending(75); // Bird song received
    tracker.increment_pending(180); // Fish feeding schedule received

    // Process some successfully
    tracker.decrement_pending_increment_processed(100); // Cat photo processed
    tracker.decrement_pending_increment_processed(250); // Dog video processed

    // Fail one
    tracker.decrement_pending_increment_failed(75); // Bird song failed

    let stats = tracker.to_stats();
    assert_eq!(stats.pending_messages, 1); // Only fish schedule pending
    assert_eq!(stats.pending_bytes, 180);
    assert_eq!(stats.total_processed, 2); // Cat and dog
    assert_eq!(stats.total_bytes_processed, 350); // 100 + 250
    assert_eq!(stats.total_failed, 1); // Bird song
}

#[test]
fn test_queue_stats_is_empty() {
    let tracker = QueueStatsTracker::new();

    assert!(tracker.is_empty());

    tracker.increment_pending(50);
    assert!(!tracker.is_empty());

    tracker.decrement_pending_increment_processed(50);
    assert!(tracker.is_empty());
}

#[test]
fn test_queue_stats_reset() {
    let tracker = QueueStatsTracker::new();

    // Add some activity
    tracker.increment_pending(100);
    tracker.decrement_pending_increment_processed(100);
    tracker.increment_pending(200);
    tracker.decrement_pending_increment_failed(200);

    let stats_before = tracker.to_stats();
    assert_eq!(stats_before.total_processed, 1);
    assert_eq!(stats_before.total_failed, 1);
    assert_eq!(stats_before.total_bytes_processed, 100);

    // Reset should clear processed/failed but not pending
    tracker.reset_counters();

    let stats_after = tracker.to_stats();
    assert_eq!(stats_after.total_processed, 0);
    assert_eq!(stats_after.total_failed, 0);
    assert_eq!(stats_after.total_bytes_processed, 0);
    // Pending counts should remain unchanged by reset
    assert_eq!(stats_after.pending_messages, 0);
    assert_eq!(stats_after.pending_bytes, 0);
}

// Tests for PublishStatsTracker creation and initial state
#[test]
fn test_publish_stats_tracker_creation() {
    let tracker = PublishStatsTracker::new();
    let stats = tracker.to_stats();

    assert_eq!(stats.total_published, 0);
    assert_eq!(stats.total_failed, 0);
    assert_eq!(stats.total_bytes_published, 0);
}

#[test]
fn test_publish_stats_increment_published() {
    let tracker = PublishStatsTracker::new();

    // Publish some messages
    tracker.increment_published(150); // Turtle update
    tracker.increment_published(300); // Lizard status
    tracker.increment_published(75); // Gecko position

    let stats = tracker.to_stats();
    assert_eq!(stats.total_published, 3);
    assert_eq!(stats.total_bytes_published, 525); // 150 + 300 + 75
    assert_eq!(stats.total_failed, 0);
}

#[test]
fn test_publish_stats_increment_failed() {
    let tracker = PublishStatsTracker::new();

    // Some successful publishes
    tracker.increment_published(200);
    tracker.increment_published(150);

    // Some failures
    tracker.increment_failed();
    tracker.increment_failed();
    tracker.increment_failed();

    let stats = tracker.to_stats();
    assert_eq!(stats.total_published, 2);
    assert_eq!(stats.total_bytes_published, 350);
    assert_eq!(stats.total_failed, 3);
}

#[test]
fn test_publish_stats_mixed_operations() {
    let tracker = PublishStatsTracker::new();

    // Simulate realistic publish pattern
    tracker.increment_published(120); // Horse gallop notification sent
    tracker.increment_failed(); // Pony message failed to send
    tracker.increment_published(280); // Donkey status update sent
    tracker.increment_published(90); // Mule location update sent
    tracker.increment_failed(); // Zebra alert failed to send
    tracker.increment_failed(); // Unicorn message failed (unrealistic but fun)

    let stats = tracker.to_stats();
    assert_eq!(stats.total_published, 3);
    assert_eq!(stats.total_bytes_published, 490); // 120 + 280 + 90
    assert_eq!(stats.total_failed, 3);
}

#[test]
fn test_publish_stats_reset() {
    let tracker = PublishStatsTracker::new();

    // Add some activity
    tracker.increment_published(500);
    tracker.increment_published(250);
    tracker.increment_failed();
    tracker.increment_failed();

    let stats_before = tracker.to_stats();
    assert_eq!(stats_before.total_published, 2);
    assert_eq!(stats_before.total_bytes_published, 750);
    assert_eq!(stats_before.total_failed, 2);

    // Reset should clear all counters
    tracker.reset_counters();

    let stats_after = tracker.to_stats();
    assert_eq!(stats_after.total_published, 0);
    assert_eq!(stats_after.total_bytes_published, 0);
    assert_eq!(stats_after.total_failed, 0);
}

// Tests for thread safety (important for real-world usage)
#[test]
fn test_queue_stats_thread_safety() {
    let tracker = Arc::new(QueueStatsTracker::new());
    let mut handles = vec![];

    // Spawn multiple threads that operate on the tracker
    for i in 0..5 {
        let tracker_clone = Arc::clone(&tracker);
        let handle = thread::spawn(move || {
            for j in 0..10 {
                let message_size = (i * 10 + j + 1) * 10; // Varying message sizes
                tracker_clone.increment_pending(message_size);

                // Sometimes process, sometimes fail
                if (i + j) % 3 == 0 {
                    tracker_clone.decrement_pending_increment_processed(message_size);
                } else if (i + j) % 7 == 0 {
                    tracker_clone.decrement_pending_increment_failed(message_size);
                }

                // Small delay to increase chance of race conditions
                thread::sleep(Duration::from_millis(1));
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    let stats = tracker.to_stats();

    // Verify that the operations completed without panicking
    // Exact values depend on timing, but should be reasonable
    assert!(stats.pending_messages + stats.total_processed + stats.total_failed > 0);
    assert!(stats.pending_bytes + stats.total_bytes_processed > 0);
}

#[test]
fn test_publish_stats_thread_safety() {
    let tracker = Arc::new(PublishStatsTracker::new());
    let mut handles = vec![];

    // Spawn multiple threads that operate on the tracker
    for i in 0..5 {
        let tracker_clone = Arc::clone(&tracker);
        let handle = thread::spawn(move || {
            for j in 0..10 {
                let message_size = (i * 10 + j + 1) * 15;

                // Sometimes succeed, sometimes fail
                if (i + j) % 4 == 0 {
                    tracker_clone.increment_failed();
                } else {
                    tracker_clone.increment_published(message_size);
                }

                thread::sleep(Duration::from_millis(1));
            }
        });
        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().unwrap();
    }

    let stats = tracker.to_stats();

    // Verify operations completed without corruption
    assert_eq!(stats.total_published + stats.total_failed, 50); // 5 threads * 10 operations each
    assert!(stats.total_bytes_published > 0);
}

// Edge case and stress tests
#[test]
fn test_queue_stats_large_numbers() {
    let tracker = QueueStatsTracker::new();

    // Test with large message sizes
    tracker.increment_pending(1_000_000); // 1MB message
    tracker.increment_pending(5_000_000); // 5MB message
    tracker.increment_pending(10_000_000); // 10MB message

    let stats = tracker.to_stats();
    assert_eq!(stats.pending_messages, 3);
    assert_eq!(stats.pending_bytes, 16_000_000);

    // Process the large messages
    tracker.decrement_pending_increment_processed(1_000_000);
    tracker.decrement_pending_increment_processed(5_000_000);
    tracker.decrement_pending_increment_processed(10_000_000);

    let final_stats = tracker.to_stats();
    assert_eq!(final_stats.pending_messages, 0);
    assert_eq!(final_stats.total_processed, 3);
    assert_eq!(final_stats.total_bytes_processed, 16_000_000);
    assert!(tracker.is_empty());
}

#[test]
fn test_publish_stats_large_numbers() {
    let tracker = PublishStatsTracker::new();

    // Test with large publish volumes
    for i in 0..1000 {
        let size = if i % 10 == 0 { 100_000 } else { 1_000 }; // Mostly small, some large
        tracker.increment_published(size);
    }

    let stats = tracker.to_stats();
    assert_eq!(stats.total_published, 1000);

    // Calculate expected bytes: 100 large messages (100,000 bytes) + 900 small (1,000 bytes)
    let expected_bytes = (100 * 100_000) + (900 * 1_000);
    assert_eq!(stats.total_bytes_published, expected_bytes);
}

#[test]
fn test_queue_stats_zero_byte_messages() {
    let tracker = QueueStatsTracker::new();

    // Test with zero-byte messages (edge case)
    tracker.increment_pending(0);
    tracker.increment_pending(0);
    tracker.increment_pending(0);

    let stats = tracker.to_stats();
    assert_eq!(stats.pending_messages, 3);
    assert_eq!(stats.pending_bytes, 0);

    tracker.decrement_pending_increment_processed(0);
    tracker.decrement_pending_increment_failed(0);

    let final_stats = tracker.to_stats();
    assert_eq!(final_stats.pending_messages, 1);
    assert_eq!(final_stats.total_processed, 1);
    assert_eq!(final_stats.total_failed, 1);
    assert_eq!(final_stats.pending_bytes, 0);
    assert_eq!(final_stats.total_bytes_processed, 0);
}

#[test]
fn test_publish_stats_zero_byte_messages() {
    let tracker = PublishStatsTracker::new();

    // Test with zero-byte publishes
    tracker.increment_published(0);
    tracker.increment_published(0);
    tracker.increment_published(0);

    let stats = tracker.to_stats();
    assert_eq!(stats.total_published, 3);
    assert_eq!(stats.total_bytes_published, 0);
}

// Tests for realistic usage patterns
#[test]
fn test_realistic_pet_monitoring_scenario() {
    let queue_tracker = QueueStatsTracker::new();
    let publish_tracker = PublishStatsTracker::new();

    // Simulate a day of pet monitoring messages

    // Morning: Pets wake up, lots of activity
    queue_tracker.increment_pending(150); // Cat food bowl sensor
    queue_tracker.increment_pending(200); // Dog activity tracker
    queue_tracker.increment_pending(80); // Bird cage door sensor
    queue_tracker.increment_pending(120); // Fish tank temperature

    // Process morning messages
    queue_tracker.decrement_pending_increment_processed(150);
    queue_tracker.decrement_pending_increment_processed(200);
    queue_tracker.decrement_pending_increment_processed(80);
    queue_tracker.decrement_pending_increment_processed(120);

    // Send notifications about pet status
    publish_tracker.increment_published(100); // "Cat has been fed"
    publish_tracker.increment_published(95); // "Dog went outside"
    publish_tracker.increment_published(75); // "Bird is active"
    publish_tracker.increment_published(85); // "Fish tank optimal"

    // Afternoon: Some issues
    queue_tracker.increment_pending(300); // Emergency: Dog escaped sensor
    queue_tracker.increment_pending(180); // Cat litter box needs cleaning

    publish_tracker.increment_failed(); // Failed to send dog escape alert
    queue_tracker.decrement_pending_increment_failed(300); // Failed to process emergency

    // Successfully handle litter box alert
    queue_tracker.decrement_pending_increment_processed(180);
    publish_tracker.increment_published(120); // "Litter box maintenance needed"

    // Evening: Quiet time
    queue_tracker.increment_pending(90); // Night vision camera check
    queue_tracker.decrement_pending_increment_processed(90);
    publish_tracker.increment_published(60); // "All pets settled for night"

    // Verify final statistics
    let queue_stats = queue_tracker.to_stats();
    let publish_stats = publish_tracker.to_stats();

    assert_eq!(queue_stats.pending_messages, 0); // All processed
    assert_eq!(queue_stats.total_processed, 6); // 4 morning + 1 litter + 1 evening
    assert_eq!(queue_stats.total_failed, 1); // Dog escape processing failed
    assert_eq!(
        queue_stats.total_bytes_processed,
        150 + 200 + 80 + 120 + 180 + 90
    );

    assert_eq!(queue_stats.total_processed, 6); // 4 morning + 1 litter + 1 evening
    assert_eq!(publish_stats.total_failed, 1); // Dog escape alert failed
    assert_eq!(
        publish_stats.total_bytes_published,
        100 + 95 + 75 + 85 + 120 + 60
    );

    assert!(queue_tracker.is_empty());
}

// Tests for QueueStats and PublishStats struct methods (if any)
#[test]
fn test_queue_stats_debug_format() {
    let tracker = QueueStatsTracker::new();
    tracker.increment_pending(100);
    tracker.decrement_pending_increment_processed(100);

    let stats = tracker.to_stats();
    let debug_str = format!("{stats:?}");

    // Should be able to debug format without panic
    assert!(debug_str.contains("QueueStats"));
    assert!(debug_str.contains("total_processed"));
}

#[test]
fn test_publish_stats_debug_format() {
    let tracker = PublishStatsTracker::new();
    tracker.increment_published(200);
    tracker.increment_failed();

    let stats = tracker.to_stats();
    let debug_str = format!("{stats:?}");

    // Should be able to debug format without panic
    assert!(debug_str.contains("PublishStats"));
    assert!(debug_str.contains("total_published"));
}

#[test]
fn test_stats_clone() {
    let tracker = QueueStatsTracker::new();
    tracker.increment_pending(150);
    tracker.decrement_pending_increment_processed(150);

    let stats1 = tracker.to_stats();
    let stats2 = stats1.clone();

    // Cloned stats should be identical
    assert_eq!(stats1.pending_messages, stats2.pending_messages);
    assert_eq!(stats1.total_processed, stats2.total_processed);
    assert_eq!(stats1.total_bytes_processed, stats2.total_bytes_processed);
}

// Performance-oriented tests
#[test]
fn test_stats_performance_no_contention() {
    let tracker = QueueStatsTracker::new();
    let start = std::time::Instant::now();

    // Perform many operations quickly
    for i in 0..10_000 {
        tracker.increment_pending(i % 1000);
        if i % 2 == 0 {
            tracker.decrement_pending_increment_processed(i % 1000);
        } else {
            tracker.decrement_pending_increment_failed(i % 1000);
        }
    }

    let elapsed = start.elapsed();

    // Should complete very quickly (atomic operations are fast)
    assert!(
        elapsed.as_millis() < 100,
        "Stats operations should be very fast"
    );

    // Verify final state is consistent
    let stats = tracker.to_stats();
    assert_eq!(stats.total_processed + stats.total_failed, 10_000);
}
