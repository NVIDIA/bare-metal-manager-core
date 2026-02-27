/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Repository pattern for DPF Kubernetes resources.
//!
//! This module provides trait-based abstractions for interacting with DPF CRDs,
//! enabling dependency injection and testability.

mod kube;
mod traits;

pub use traits::*;

pub use self::kube::KubeRepository;
