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

use std::path::PathBuf;

/// Failure while compiling or loading protobuf descriptors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Temporary storage for the descriptor output could not be created.
    #[error("failed to create temporary protobuf descriptor storage")]
    CreateTemporaryDescriptor {
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// The protobuf frontend failed.
    #[error("failed to compile protobuf descriptors")]
    CompileProtobuf {
        /// Error reported by prost-build or `protoc`.
        #[source]
        source: std::io::Error,
    },

    /// The raw descriptor set emitted by `protoc` could not be read.
    #[error("failed to read protobuf descriptor set from `{path}`")]
    ReadDescriptorSet {
        /// Descriptor output path.
        path: PathBuf,
        /// Underlying filesystem error.
        #[source]
        source: std::io::Error,
    },

    /// The raw descriptor bytes could not be decoded into a descriptor pool.
    #[error("failed to decode protobuf descriptor pool")]
    DecodeDescriptorPool {
        /// Descriptor decoding error.
        #[source]
        source: prost_reflect::DescriptorError,
    },

    /// A required code-generation extension was not present in the schema.
    #[error("protobuf code-generation extension `{0}` is missing")]
    MissingCodegenExtension(&'static str),

    /// A code-generation extension has an unexpected protobuf type.
    #[error("protobuf code-generation extension `{0}` has an invalid shape")]
    InvalidCodegenExtension(String),

    /// A derive annotation is not a valid Rust path.
    #[error("invalid rust derive `{derive}` on protobuf type `{protobuf_type}`")]
    InvalidRustDerive {
        /// Fully qualified protobuf type name.
        protobuf_type: String,
        /// Invalid derive annotation.
        derive: String,
        /// Rust parser error.
        #[source]
        source: syn::Error,
    },
}
