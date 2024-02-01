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

use serde::{Deserialize, Serialize};

/// State of an entry inside the resource pool
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ResourcePoolEntryState {
    /// The resource is not used
    Free,
    /// The resource is allocated by a certain owner
    Allocated { owner: String, owner_type: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_resource_pool_entry_state() {
        let state = ResourcePoolEntryState::Free;
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, r#"{"state":"free"}"#);
        assert_eq!(
            serde_json::from_str::<ResourcePoolEntryState>(&serialized).unwrap(),
            state
        );

        let state = ResourcePoolEntryState::Allocated {
            owner: "me".to_string(),
            owner_type: "my_stuff".to_string(),
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serialized,
            r#"{"state":"allocated","owner":"me","owner_type":"my_stuff"}"#
        );
        assert_eq!(
            serde_json::from_str::<ResourcePoolEntryState>(&serialized).unwrap(),
            state
        );
    }
}
