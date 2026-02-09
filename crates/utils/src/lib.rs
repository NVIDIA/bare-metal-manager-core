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
use std::collections::{BTreeMap, HashMap};
use std::hash::Hash;

use serde::{Serialize, Serializer};

pub mod cmd;
mod host_port_pair;
pub mod managed_host_display;
pub mod models;
pub mod sku;

pub use host_port_pair::{HostPortPair, HostPortParseError};
pub use managed_host_display::{ManagedHostMetadata, ManagedHostOutput, get_managed_host_output};
pub const DEFAULT_DPU_DMI_BOARD_SERIAL_NUMBER: &str = "Unspecified Base Board Serial Number";
pub const DEFAULT_DPU_DMI_CHASSIS_SERIAL_NUMBER: &str = "Unspecified Chassis Board Serial Number";
pub const DEFAULT_DMI_SYSTEM_MANUFACTURER: &str = "Unspecified System Manufacturer";
pub const DEFAULT_DMI_SYSTEM_MODEL: &str = "Unspecified Model";
pub const BF2_PRODUCT_NAME: &str = "BlueField SoC";
pub const BF3_PRODUCT_NAME: &str = "BlueField-3 SmartNIC Main Card";

/// A string to display to the user. Either the 'reason' or 'err' field, or None.
pub fn reason_to_user_string(p: &rpc::forge::ControllerStateReason) -> Option<String> {
    use rpc::forge::ControllerStateOutcome::*;
    let Ok(outcome) = rpc::forge::ControllerStateOutcome::try_from(p.outcome) else {
        tracing::error!("Invalid rpc::forge::ControllerStateOutcome i32, should be impossible.");
        return None;
    };
    match outcome {
        Transition | DoNothing | Todo => None,
        Wait | Error => p.outcome_msg.clone(),
    }
}

// ordered_map is used with serde to take a HashMap and always serialize it in key sorted order
pub fn ordered_map<S, K: Ord + Serialize, V: Serialize>(
    value: &HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    ordered.serialize(serializer)
}

pub fn has_duplicates<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut uniq = std::collections::HashSet::new();
    !iter.into_iter().all(move |x| uniq.insert(x))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_duplicates() {
        assert!(!has_duplicates(vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "4".to_string()
        ]));
        assert!(has_duplicates(vec![
            "1".to_string(),
            "2".to_string(),
            "3".to_string(),
            "2".to_string(),
            "4".to_string()
        ]));
        assert!(!has_duplicates(vec![1, 2, 3, 4, 5]));
        assert!(has_duplicates(vec![1, 2, 3, 4, 5, 1]));

        let v1 = vec!["1", "3"];
        // call  has_duplicates using ref
        println!("{}", has_duplicates(&v1));
        assert_eq!(v1.len(), 2);
    }
}
