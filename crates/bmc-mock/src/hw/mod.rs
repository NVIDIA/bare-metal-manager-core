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

//! Submodules of this module defines support of specific hardware
//! (i.e. how this hardware is represented via Redfish).

/// Description of NIC card.
pub mod nic;

/// Support of NVIDIA Bluefield3 DPU.
pub mod bluefield3;

/// Support of Dell PowerEdge R750 servers.
pub mod dell_poweredge_r750;

/// Support of Wiwynn GB200 NVL servers.
pub mod wiwynn_gb200_nvl;
