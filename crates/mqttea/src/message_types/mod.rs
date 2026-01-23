/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// src/message_types/mod.rs
//
// First-class message types beyond protobufs,
// JSON, and YAML. Right now it's just the "raw"
// type, oh and the "string" type now too!

pub mod raw;
pub mod string;
pub use raw::RawMessage;
pub use string::StringMessage;
