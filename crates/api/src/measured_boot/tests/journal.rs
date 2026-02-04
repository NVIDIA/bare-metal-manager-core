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

//! tests/journal.rs
//!
//! Journal:
//! [ ] test_journal_crudl: Make sure basic CRUDL works as expected.

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use carbide_uuid::machine::MachineId;
    use carbide_uuid::measured_boot::{MeasurementReportId, MeasurementSystemProfileId};
    use measured_boot::records::MeasurementMachineState;

    // test_journal_crudl makes sure database constraints
    // are honored for inserting new journal entries.
    #[crate::sqlx_test]
    pub async fn test_journal_crudl(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;
        let machine_id =
            MachineId::from_str("fm100hseddco33hvlofuqvg543p6p9aj60g76q5cq491g9m9tgtf2dk0530")?;
        let report_id = MeasurementReportId::new();
        let profile_id = MeasurementSystemProfileId::new();
        let journal = db::measured_boot::journal::new(
            &mut txn,
            machine_id,
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
