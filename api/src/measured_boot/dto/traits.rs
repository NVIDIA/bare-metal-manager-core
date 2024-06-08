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
 *  These are traits to make the generic functions in db/interface/common.rs
 *  be able to do what they do. Look dto/keys.rs and dto/records.rs
 *  for implementaton.
*/

/// DbPrimaryUuid is a trait intended for primary keys which
/// derive the sqlx UUID type. The intent is the db_primary_uuid_name
/// function should return the name of the column for the primary
/// UUID-typed key, which allows dynamic compositon of a SQL query.
pub trait DbPrimaryUuid {
    fn db_primary_uuid_name() -> &'static str;
}

/// DbTable is a trait intended for table records which derive
/// sqlx FromRow. The intent here is db_table_name() will return
/// the actual name of the table the records are in, allowing for
/// dynamic composition of an SQL query for that table.
pub trait DbTable {
    fn db_table_name() -> &'static str;
}
