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

use jsonwebtoken as jst;
use nras::{KeyStore, NrasError};

pub struct MockKeyStore {
    key: Option<jst::DecodingKey>,
}

impl MockKeyStore {
    pub fn new_with_key(x: &str, y: &str) -> MockKeyStore {
        let key = jst::DecodingKey::from_ec_components(x, y)
            .map_err(|e| NrasError::Jwk(format!("Error creating DecodingKey from EC PEM: {}", e)))
            .unwrap();

        MockKeyStore { key: Some(key) }
    }

    pub fn new_with_no_key() -> MockKeyStore {
        MockKeyStore { key: None }
    }
}

impl KeyStore for MockKeyStore {
    fn find_key(&self, _kid: &str) -> Option<jst::DecodingKey> {
        self.key.clone()
    }
}
