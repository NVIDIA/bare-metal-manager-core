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
pub fn capacity_string(size_mb: u64) -> String {
    match byte_unit::Byte::from_u64_with_unit(size_mb, byte_unit::Unit::MiB) {
        Some(byte) => byte
            .get_appropriate_unit(byte_unit::UnitType::Binary)
            .to_string(),
        None => "Invalid".to_string(),
    }
}
