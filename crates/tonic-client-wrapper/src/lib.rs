/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// Note: codegen isn't needed at runtime... dependents should enable this feature in their build-dependencies and disable it otherwise.
#[cfg(feature = "codegen")]
pub mod codegen;
#[cfg(feature = "codegen")]
mod utils;

/// A ConnectionProvider is needed by the generated tonic wrapper to get the actual connection to
/// the server when needed. This is the only thing needed at runtime. This allows
/// tonic-client-wrapper to be agnostic to how connections are actually made to the server.
#[async_trait::async_trait]
pub trait ConnectionProvider<T: Clone>: Send + Sync + std::fmt::Debug + 'static {
    /// Function which provides a connection.
    ///
    /// The Connection type, T, is the code-generated type from tonic_build that contains all the
    /// RPC methods this crate will be wrapping. It needs to be `Clone` so that it can be used by
    /// multiple clients at once. (Typically you'd use tower's `BoxCloneService` or similar for
    /// this.)
    async fn provide_connection(&self) -> Result<T, tonic::Status>;

    /// Return true if the connection needs to be recreated on the next RPC call. This can be the
    /// case if, for instance, the client certificate on the filesystem has a newer modification
    /// date than the last connection date (indicating we need to use the new client cert.)
    async fn connection_is_stale(&self, last_connected: std::time::SystemTime) -> bool;

    /// Return the server URL for the connection, for debug/logging purposes.
    fn connection_url(&self) -> &str;
}
