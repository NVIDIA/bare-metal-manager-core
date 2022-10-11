/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::time::SystemTime;

use chrono::DateTime;
use itertools::Itertools;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

pub mod configuration_resource_pool;
pub mod leaf;
pub mod managed_resource;
pub mod resource_group;

pub trait VpcResource {
    type Status: VpcResourceStatus;

    fn status(&self) -> Option<&Self::Status>;
    fn metadata(&self) -> &ObjectMeta;
    fn vpc_resource_name(&self) -> Option<&String> {
        self.metadata().name.as_ref()
    }
}

pub trait VpcResourceCondition {
    fn timestamp(&self) -> Option<&str>;
}

pub trait VpcResourceStatus {
    fn is_ready(&self) -> bool;
}

pub trait VpcResourceMetadata {
    fn name(&self) -> Option<&String>;
}

fn latest_condition<C: VpcResourceCondition>(conditions: &[C]) -> Option<&C> {
    let default_timestamp: &str = "0";

    conditions
        .iter()
        .sorted_by_key(|condition_to_be_sorted| {
            let time_stamp = condition_to_be_sorted
                .timestamp()
                .unwrap_or(default_timestamp);

            if let Ok(duration) = chrono::DateTime::parse_from_rfc3339(time_stamp) {
                duration
                    .signed_duration_since(DateTime::<chrono::Utc>::from(SystemTime::UNIX_EPOCH))
                    .num_milliseconds() as u64
            } else {
                0
            }
        })
        .last()
}

impl VpcResource for leaf::Leaf {
    type Status = leaf::LeafStatus;
    fn status(&self) -> Option<&Self::Status> {
        self.status.as_ref()
    }
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl VpcResourceStatus for leaf::LeafStatus {
    fn is_ready(&self) -> bool {
        if let Some(conditions) = self.conditions.as_ref() {
            if let Some(condition) = latest_condition(conditions) {
                if let Some(condition_status) = condition.status.as_ref() {
                    if condition_status.to_lowercase().as_str() != "true" {
                        return false;
                    }

                    if let Some(host_admin_ips) = self.host_admin_i_ps.as_ref() {
                        return !host_admin_ips.is_empty();
                    }
                }
            }
        }
        false
    }
}

impl VpcResourceCondition for leaf::LeafStatusConditions {
    fn timestamp(&self) -> Option<&str> {
        self.last_transition_time.as_deref()
    }
}

impl VpcResource for resource_group::ResourceGroup {
    type Status = resource_group::ResourceGroupStatus;
    fn status(&self) -> Option<&Self::Status> {
        self.status.as_ref()
    }
    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

impl VpcResourceStatus for resource_group::ResourceGroupStatus {
    fn is_ready(&self) -> bool {
        if let Some(conditions) = self.conditions.as_ref() {
            if let Some(condition) = latest_condition(conditions) {
                if let Some(condition_status) = condition.status.as_ref() {
                    return condition_status.to_lowercase().as_str() == "true";
                }
            }
        }
        false
    }
}

impl VpcResourceCondition for resource_group::ResourceGroupStatusConditions {
    fn timestamp(&self) -> Option<&str> {
        self.last_transition_time.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE_TIME: &str = "2022-09-29T16:40:49Z";
    const NEW_TIME: &str = "2022-09-29T18:40:49Z";

    #[test]
    fn latest_condition_time_is_newest_timestamp() {
        let last_transition_time_1 = chrono::DateTime::parse_from_rfc3339(BASE_TIME)
            .expect("Unable to convert transition time");

        let last_transition_time_1 = last_transition_time_1
            .signed_duration_since(DateTime::<chrono::Utc>::from(SystemTime::UNIX_EPOCH))
            .num_milliseconds() as u64;

        let last_transition_time_2 = chrono::DateTime::parse_from_rfc3339(NEW_TIME)
            .expect("Unable to convert transition time");
        let last_transition_time_2 = last_transition_time_2
            .signed_duration_since(DateTime::<chrono::Utc>::from(SystemTime::UNIX_EPOCH))
            .num_milliseconds() as u64;

        let current_leaf_status_condition = leaf::LeafStatusConditions {
            last_transition_time: Some(last_transition_time_1.to_string()),
            message: Some(format!(
                "I'm a condition at time {}",
                last_transition_time_1
            )),
            status: Some("true".to_string()),
            r#type: Some("Liveness".to_string()),
        };

        let new_leaf_status_condition = leaf::LeafStatusConditions {
            last_transition_time: Some(last_transition_time_2.to_string()),
            message: Some(format!(
                "I am a condition at time {}",
                last_transition_time_2
            )),
            status: Some("true".to_string()),
            r#type: Some("Liveness".to_string()),
        };

        let conditions_array = vec![
            current_leaf_status_condition,
            new_leaf_status_condition.clone(),
        ];
        let res = latest_condition(&conditions_array);

        if let Some(result) = res {
            if let Some(last) = &result.last_transition_time {
                assert_eq!(
                    last.to_owned(),
                    new_leaf_status_condition.last_transition_time.unwrap()
                );
                if let Some(message) = &result.message {
                    assert_eq!(
                        message.to_owned(),
                        format!("I am a condition at time {}", last_transition_time_2)
                    )
                }
            }
        }
    }
}
