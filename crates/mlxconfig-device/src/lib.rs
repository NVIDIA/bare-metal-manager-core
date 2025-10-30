/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
// cmd module contains command-line interface logic and command handlers.
pub mod cmd;
// discovery module handles device discovery and enumeration using mlxfwmanager.
pub mod discovery;
// filters module provides filtering capabilities for device queries.
pub mod filters;
// info module defines the core device information structures.
pub mod info;
// proto module contains code for translating to/from protobuf
pub mod proto;
// report module contains the MlxDeviceReport and helpers.
pub mod report;
