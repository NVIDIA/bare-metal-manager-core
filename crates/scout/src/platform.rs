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

use smbioslib::{SMBiosSystemInformation, table_load_from_device};

/// Returns `true` when scout is running on a managed host (as opposed to a DPU).
pub(crate) fn is_host() -> bool {
    match table_load_from_device() {
        Ok(data) => data.any(|sys_info: SMBiosSystemInformation| {
            !sys_info
                .product_name()
                .to_string()
                .to_lowercase()
                .contains("bluefield")
        }),
        Err(_err) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_host_returns_bool_without_panicking() {
        let _ = is_host();
    }
}
