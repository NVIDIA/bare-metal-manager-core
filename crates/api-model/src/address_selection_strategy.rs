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

#[derive(Clone, Copy)]
pub enum AddressSelectionStrategy {
    /// Allocate the next available single IP address.
    /// Uses /32 for IPv4 prefixes, /128 for IPv6 prefixes.
    NextAvailableIp,

    /// Alias for `NextAvailableIp`. Kept for backwards compatibility.
    Automatic,

    /// Allocate the next available prefix of the given length.
    /// For example, `NextAvailablePrefix(30)` allocates a /30 block
    /// (used by FNN to allocate a 4-address subnet per DPU).
    NextAvailablePrefix(u8),
}
