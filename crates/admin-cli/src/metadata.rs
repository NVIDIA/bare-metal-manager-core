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

pub(crate) fn get_nice_labels_from_rpc_metadata(metadata: Option<&Metadata>) -> Vec<String> {
    metadata
        .map(|m| {
            m.labels
                .iter()
                .map(|label| {
                    let key = &label.key;
                    let value = label.value.as_deref().unwrap_or_default();
                    format!("\"{key}:{value}\"")
                })
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn parse_rpc_labels(labels: Vec<String>) -> Vec<rpc::forge::Label> {
    labels
        .into_iter()
        .map(|label| match label.split_once(':') {
            Some((k, v)) => rpc::forge::Label {
                key: k.trim().to_string(),
                value: Some(v.trim().to_string()),
            },
            None => rpc::forge::Label {
                key: if label.contains(char::is_whitespace) {
                    label.trim().to_string()
                } else {
                    // avoid allocations on the happy path
                    label
                },
                value: None,
            },
        })
        .collect()
}
