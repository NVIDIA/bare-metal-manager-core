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

use std::future;

use futures_util::FutureExt;
use tokio::sync::oneshot;

/// Convenience trait for a task with a shutdown handle (in the form of a [`oneshot::Sender<()>`])
///
/// The shutdown handle must be treated such that dropping it means "shut down now", (because any
/// call which is awaiting the channel will immediately return.) By convention, dropping the
/// channel and sending the shutdown message mean the same thing.
pub trait ShutdownHandle<R> {
    fn into_parts(self) -> (oneshot::Sender<()>, tokio::task::JoinHandle<R>);

    fn shutdown_and_wait(self) -> impl std::future::Future<Output = R> + Send
    where
        Self: Send + Sized,
        R: Send,
    {
        async move {
            let (shutdown_tx, join_handle) = self.into_parts();
            // Let the shutdown handle drop, which causes any reads to finish (semantically the same as
            // sending an empty tuple over the channel, both mean "shut down now").
            std::mem::drop(shutdown_tx);
            join_handle.await.expect("task panicked")
        }
    }
}

pub trait ReadyHandle {
    fn take_ready_rx(&mut self) -> Option<oneshot::Receiver<()>>;

    fn wait_until_ready(
        &mut self,
    ) -> impl std::future::Future<Output = Result<(), oneshot::error::RecvError>> + Send {
        if let Some(ready_rx) = self.take_ready_rx() {
            ready_rx.boxed()
        } else {
            future::ready(Ok(())).boxed()
        }
    }
}
