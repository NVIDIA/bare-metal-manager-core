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

pub mod convert;
pub mod drain;

#[allow(clippy::all)]
pub mod opentelemetry {
    pub mod proto {
        pub mod common {
            pub mod v1 {
                tonic::include_proto!("opentelemetry.proto.common.v1");
            }
        }
        pub mod resource {
            pub mod v1 {
                tonic::include_proto!("opentelemetry.proto.resource.v1");
            }
        }
        pub mod logs {
            pub mod v1 {
                tonic::include_proto!("opentelemetry.proto.logs.v1");
            }
        }
        pub mod collector {
            pub mod logs {
                pub mod v1 {
                    tonic::include_proto!("opentelemetry.proto.collector.logs.v1");
                }
            }
        }
    }
}

pub use opentelemetry::proto::collector::logs::v1 as collector_logs;
pub use opentelemetry::proto::common::v1 as common;
pub use opentelemetry::proto::logs::v1 as logs;
pub use opentelemetry::proto::resource::v1 as resource;
