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

///////////////////////////////////////////////////////////////////////////////
/// tests/journal.rs
///
/// Journal:
/// [ ] test_journal_crudl: Make sure basic CRUDL works as expected.
///////////////////////////////////////////////////////////////////////////////

#[cfg(test)]
mod tests {
    use crate::measured_boot::dto::keys::{
        MeasurementReportId, MeasurementSystemProfileId, MockMachineId,
    };
    use crate::measured_boot::dto::records::MeasurementMachineState;
    use crate::measured_boot::model::journal::MeasurementJournal;

    // test_journal_crudl makes sure database constraints
    // are honored for inserting new journal entries.
    #[sqlx::test]
    pub async fn test_journal_crudl(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id = MockMachineId("princess-network".to_string());
        let report_id = MeasurementReportId(uuid::Uuid::new_v4());
        let profile_id = MeasurementSystemProfileId(uuid::Uuid::new_v4());
        let journal = MeasurementJournal::new_with_txn(
            &mut txn,
            machine_id.clone(),
            report_id,
            Some(profile_id),
            None,
            MeasurementMachineState::Discovered,
        )
        .await;

        assert!(journal.is_err());
        Ok(())
    }
}
