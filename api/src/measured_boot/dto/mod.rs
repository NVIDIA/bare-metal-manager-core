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

/*!
 * The `dto` module provides basic data transfer objects used
 * for modeling the record stored in the database.
 *
 * This includes objects for:
 * `keys`: Every primary key gets its own strongly typed instance.
 * `records`: Every database record gets its own type.
 * `traits`: Some basic traits that are used extensively by `interface`.
*/

pub mod keys;
pub mod records;
