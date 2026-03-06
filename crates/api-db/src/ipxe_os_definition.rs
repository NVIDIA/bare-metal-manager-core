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

use carbide_ipxe_renderer::IpxeOs;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::DatabaseError;

/// Fetches an iPXE OS definition by id.
///
/// Returns the definition for use with the template-based iPXE renderer.
/// The backing store for this data is expected to be added in a future migration;
/// until then, this returns NotFound.
pub async fn get(
    _txn: &mut PgConnection,
    id: Uuid,
) -> Result<IpxeOs, DatabaseError> {
    let _ = _txn;
    Err(DatabaseError::NotFoundError {
        kind: "IpxeOsDefinition",
        id: id.to_string(),
    })
}
