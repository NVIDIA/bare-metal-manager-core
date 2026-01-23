/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use rpc::Metadata;

pub(crate) fn get_nice_labels_from_rpc_metadata(metadata: &Option<Metadata>) -> Vec<String> {
    let default_metadata = Default::default();
    metadata
        .as_ref()
        .unwrap_or(&default_metadata)
        .labels
        .iter()
        .map(|label| {
            let key = &label.key;
            let value = label.value.clone().unwrap_or_default();
            format!("\"{key}:{value}\"")
        })
        .collect()
}
