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

pub mod domain;
pub mod domain_metadata;
pub mod resource_record;

pub fn normalize_domain(name: &str) -> String {
    let normalize_domain = name.trim_end_matches('.').to_lowercase();
    tracing::debug!("Normalized domain name: {} to: {}", name, normalize_domain);
    normalize_domain
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_normalize_domain_name() {
        let domain_name = "example.com.";
        let expected = "example.com";
        let normalized = super::normalize_domain(domain_name);
        assert_eq!(normalized, expected);
    }
}
