//! Runtime writer for the credential-rotation bookkeeping tables.
//!
//! `device_credential_rotation` records, per device and credential type, the
//! version of the site-wide credential currently applied on the hardware -- the
//! convergence marker the rotation engine drives toward
//! `sitewide_credential_rotation.target_version`.
//!
//! Already-ingested devices are populated once by the
//! `*_credential_rotation_backfill` data migration. This module records the
//! same fact at runtime, at the moment NICo actually sets a credential on a
//! device (factory -> site-wide at ingestion), so the table does not go stale
//! as new sites and new hardware are adopted. The migration handles "before the
//! upgrade"; these hooks handle "ever after".
//!
//! Ingestion hooks wired today (calling [`record_device_converged`]) record the
//! fact at the moment NICo writes the credential, not when the device row is
//! later persisted:
//!
//! * `bmc` -- at `site-explorer` `BmcEndpointExplorer::set_bmc_root_credentials`,
//!   the single point where every host, DPU, switch, and power-shelf BMC is
//!   moved onto (or confirmed on) the site-wide root and its per-device Vault
//!   secret is written.
//! * `host_uefi` -- when the host UEFI password is set on the device
//!   (`api-core` `set_host_uefi_password` and the machine-controller UEFI-setup
//!   state, alongside stamping `machines.bios_password_set_time`).
//! * `dpu_uefi` -- when the DPU UEFI password is set on the device, at the
//!   machine-controller `DpuInitState::WaitingForPlatformConfiguration` state
//!   right after `uefi_setup(dpu = true)` succeeds (keyed by the DPU BMC MAC,
//!   mirroring the backfill).
//! * `lockdown_ikm` -- staged as a two-phase rotation keyed by the card (NIC)
//!   MAC, so the recorded convergence version is always the one the hardware was
//!   actually locked under rather than the (mutable) site-wide target re-read at
//!   observation time. When api-core issues the lock command it stamps the IKM
//!   version the lock key was derived from as the in-flight marker via
//!   [`mark_device_rotating_to_version`] (`rotating_to_version`); when
//!   dpa-manager `handle_locking` sees the card report Locked
//!   (`card_state.lockmode == Locked`) it promotes that exact value to
//!   `current_version` via [`promote_rotating_to_current`]. A card with no staged
//!   marker (locked before this flow shipped, already at v0 from the backfill)
//!   falls back to [`record_device_converged`] at the site-wide target. Today the
//!   locked-with version is `CURRENT_LOCKDOWN_IKM_VERSION` (0); the rotation
//!   engine will own advancing the site-wide target, and the staged
//!   `rotating_to_version` is exactly the crash-safety marker that keeps a
//!   mid-flight advance from mis-recording a card as converged to a version it
//!   was never locked under.
//!
//! Deferred to the work that owns those write paths:
//!
//! * `nvos` -- the hook is wired in the switch controller at
//!   `configuring::handle_rotate_os_password` (the `RotateOsPassword` state) but
//!   gated off, because NICo only copies the operator-provided NVOS credential
//!   into Vault today; it does not change the switch password (REQ-6,
//!   set-NVOS-from-factory, is not implemented). The gate flips on with REQ-6.
//!
//! Teardown hooks (calling [`delete_device_converged`]) remove a marker when the
//! credential it tracks is torn down, keeping the table honest:
//!
//! * `bmc` -- at `api-core` `delete_bmc_root_credentials_by_mac`, alongside
//!   deleting the per-device BMC secret from Vault. Once NICo discards the
//!   secret it can no longer authenticate or rotate, so the marker is meaningless.
//! * `host_uefi` -- in the `api-core` force-delete path, right after
//!   `clear_host_uefi_password` resets the password on the device: the host no
//!   longer carries the site-wide UEFI value, so the marker is false.
//!
//! Markers NICo does *not* tear down (the device keeps the site-wide credential,
//! or NICo keeps the secret) are left to the rotation engine, which must always
//! join `device_credential_rotation` to the live device tables when selecting
//! work so a row orphaned by device deletion is never acted on.

use mac_address::MacAddress;
use sqlx::PgConnection;

use crate::DatabaseError;

/// Mirrors the `credential_rotation_type` Postgres enum
/// (`20260623120000_credential_rotation.sql`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "credential_rotation_type", rename_all = "snake_case")]
pub enum CredentialRotationType {
    Bmc,
    HostUefi,
    DpuUefi,
    Nvos,
    LockdownIkm,
}

/// Records that `device_mac` now carries the current site-wide `credential_type`
/// credential, i.e. it has converged to the active `target_version`.
///
/// Call this right after NICo sets the credential on the device (the factory ->
/// site-wide step at ingestion). The recorded `current_version` is the
/// credential type's current site-wide `target_version`, so a device ingested
/// during or after a rotation is recorded at the version it actually received.
///
/// Requires a `sitewide_credential_rotation` row for `credential_type` to
/// already exist; the backfill migration seeds one for every active type. If it
/// is absent this returns [`DatabaseError::MissingSitewideRotationTarget`]
/// rather than guessing a version -- see the body for why guessing is unsafe.
///
/// Idempotent: an existing row (re-ingestion, retry, or the backfill migration)
/// is left untouched, so this never clobbers a version the rotation engine is
/// tracking -- the engine owns all subsequent version transitions.
pub async fn record_device_converged(
    conn: &mut PgConnection,
    device_mac: MacAddress,
    credential_type: CredentialRotationType,
) -> Result<(), DatabaseError> {
    // Resolve the site-wide target up front and fail loudly if it is missing.
    //
    // For every credential type wired today (bmc, host_uefi, dpu_uefi,
    // lockdown_ikm) the backfill data migration unconditionally seeds a
    // `sitewide_credential_rotation` row, so an absent row is never a normal
    // condition -- it is a corrupted invariant. The previous COALESCE(..., 0)
    // masked that: it recorded `current_version = 0`, which may be the wrong
    // convergence version (the device actually received whatever the live
    // target was), and the `ON CONFLICT DO NOTHING` below then froze that wrong
    // value forever (the engine owns transitions and never clobbers it). Once
    // the site-wide row was restored the engine would see `0 < target` and
    // drive a spurious rotation of a security credential. Erroring instead
    // surfaces the broken state and lets it self-heal once the row exists.
    //
    // NVOS is deliberately NOT backfilled, and its only caller
    // (switch-controller `handle_configuring`) is gated off until REQ-6. When
    // that gate flips on, REQ-6 MUST also seed a `sitewide_credential_rotation`
    // row for nvos (via the backfill or at runtime) before this is called, or
    // it will -- correctly -- fail with `MissingSitewideRotationTarget` instead
    // of recording a bogus version. The error makes that ordering
    // self-enforcing.
    //
    // Resolving the target here and recording it is correct only when the
    // device is known to carry the *current* site-wide credential -- i.e. NICo
    // just set factory -> site-wide. A caller that locked/derived against a
    // specific version it captured earlier must instead stage that version with
    // [`mark_device_rotating_to_version`] and promote it on confirmation with
    // [`promote_rotating_to_current`], so a target advancing between derivation
    // and confirmation cannot mis-record the convergence version.
    let select = "SELECT target_version FROM sitewide_credential_rotation \
                  WHERE credential_type = $1";
    let target_version: i32 = sqlx::query_scalar(select)
        .bind(credential_type)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| DatabaseError::query(select, e))?
        .ok_or(DatabaseError::MissingSitewideRotationTarget(
            credential_type,
        ))?;

    // Idempotent: an existing row (re-ingestion, retry, or the backfill
    // migration) is left untouched, so we never clobber a version the rotation
    // engine is tracking -- the engine owns all subsequent transitions.
    let insert = "INSERT INTO device_credential_rotation \
                      (device_mac, credential_type, current_version) \
                  VALUES ($1, $2, $3) \
                  ON CONFLICT (device_mac, credential_type) DO NOTHING";
    sqlx::query(insert)
        .bind(device_mac)
        .bind(credential_type)
        .bind(target_version)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(insert, e))
}

/// Stages an in-flight rotation: records that `device_mac` is being moved to
/// `rotating_to_version` of `credential_type`, without touching `current_version`.
///
/// This is phase one of a two-phase convergence for credentials NICo derives
/// against a specific version it must remember (the lockdown-IKM lock flow is the
/// motivating case): api-core calls this when it *issues* the lock command,
/// capturing the exact IKM version the key was derived from. dpa-manager then
/// calls [`promote_rotating_to_current`] when the hardware confirms, so the
/// recorded convergence version is the one the card was actually locked under
/// rather than the site-wide target re-read at observation time (which may have
/// advanced in between).
///
/// Upserts so it works whether or not a row exists yet, and is idempotent across
/// retry scout cycles: the lock command is re-derived from the same version every
/// cycle, so the conditional `DO UPDATE` only writes when the staged value
/// actually changes. `current_version` is left as-is (NULL "not yet established"
/// for a first lock, or the prior converged value for a real rotation). The
/// non-negative CHECK on the column is the final guard against a bad version.
pub async fn mark_device_rotating_to_version(
    conn: &mut PgConnection,
    device_mac: MacAddress,
    credential_type: CredentialRotationType,
    rotating_to_version: i32,
) -> Result<(), DatabaseError> {
    let query = "INSERT INTO device_credential_rotation \
                     (device_mac, credential_type, rotating_to_version) \
                 VALUES ($1, $2, $3) \
                 ON CONFLICT (device_mac, credential_type) \
                 DO UPDATE SET rotating_to_version = EXCLUDED.rotating_to_version \
                 WHERE device_credential_rotation.rotating_to_version \
                       IS DISTINCT FROM EXCLUDED.rotating_to_version";
    sqlx::query(query)
        .bind(device_mac)
        .bind(credential_type)
        .bind(rotating_to_version)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Completes an in-flight rotation: promotes a staged `rotating_to_version` to
/// `current_version` for `(device_mac, credential_type)` and clears the in-flight
/// marker. Returns `true` if a staged rotation was promoted, `false` if there was
/// nothing to promote (no row, or `rotating_to_version` already NULL).
///
/// Phase two of the flow started by [`mark_device_rotating_to_version`]: called
/// when the hardware confirms the new credential. Because the promoted value is
/// the exact version staged at derivation time, a site-wide target that advanced
/// in between cannot make us record a version the hardware was never on.
///
/// Idempotent: a second call (e.g. a re-observed lock) finds `rotating_to_version`
/// already cleared and is a no-op, leaving the promoted `current_version` intact.
/// A `false` return lets the caller fall back to [`record_device_converged`] for
/// devices that were converged before this staged flow shipped (no marker).
pub async fn promote_rotating_to_current(
    conn: &mut PgConnection,
    device_mac: MacAddress,
    credential_type: CredentialRotationType,
) -> Result<bool, DatabaseError> {
    let query = "UPDATE device_credential_rotation \
                 SET current_version = rotating_to_version, rotating_to_version = NULL \
                 WHERE device_mac = $1 AND credential_type = $2 \
                       AND rotating_to_version IS NOT NULL";
    let result = sqlx::query(query)
        .bind(device_mac)
        .bind(credential_type)
        .execute(&mut *conn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(result.rows_affected() > 0)
}

/// Deletes the convergence row for `(device_mac, credential_type)`, if present.
///
/// Call this when NICo tears down the credential the row tracks -- either by
/// discarding its only copy (the per-device BMC secret deleted from Vault on
/// force-delete / `DeleteCredential`) or by changing it back on the device (the
/// host UEFI password cleared on force-delete). Once the credential the marker
/// depends on is gone, the marker is false and must not linger for the rotation
/// engine to act on. Idempotent: deleting a missing row is a no-op.
pub async fn delete_device_converged(
    conn: &mut PgConnection,
    device_mac: MacAddress,
    credential_type: CredentialRotationType,
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM device_credential_rotation \
                 WHERE device_mac = $1 AND credential_type = $2";
    sqlx::query(query)
        .bind(device_mac)
        .bind(credential_type)
        .execute(conn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

// Tests for the SQL-only `*_credential_rotation_backfill` data migration. It has
// no Rust counterpart to host an inline `mod tests`, so it lives as a sibling
// child module here (mirroring `machine_interface::test_duplicate_mac`) rather
// than as a standalone top-level module.
#[cfg(test)]
mod test_backfill;

#[cfg(test)]
mod tests {
    use mac_address::MacAddress;
    use sqlx::{PgConnection, PgPool};

    use super::{
        CredentialRotationType, delete_device_converged, mark_device_rotating_to_version,
        promote_rotating_to_current, record_device_converged,
    };
    use crate::DatabaseError;

    // current_version for a (mac, type) row, or None if no row exists. Takes the
    // same connection the writers use (rather than the pool) so the whole test
    // runs on a single connection -- otherwise holding that connection across a
    // second `pool` acquisition trips the txn_held_across_await lint.
    async fn version_of(conn: &mut PgConnection, mac: &str, credential_type: &str) -> Option<i32> {
        let row: Option<Option<i32>> = sqlx::query_scalar(
            "SELECT current_version FROM device_credential_rotation \
             WHERE device_mac = $1::macaddr \
               AND credential_type = $2::credential_rotation_type",
        )
        .bind(mac)
        .bind(credential_type)
        .fetch_optional(&mut *conn)
        .await
        .unwrap();
        row.flatten()
    }

    // rotating_to_version for a (mac, type) row, or None if no row exists or no
    // rotation is staged.
    async fn rotating_version_of(
        conn: &mut PgConnection,
        mac: &str,
        credential_type: &str,
    ) -> Option<i32> {
        let row: Option<Option<i32>> = sqlx::query_scalar(
            "SELECT rotating_to_version FROM device_credential_rotation \
             WHERE device_mac = $1::macaddr \
               AND credential_type = $2::credential_rotation_type",
        )
        .bind(mac)
        .bind(credential_type)
        .fetch_optional(&mut *conn)
        .await
        .unwrap();
        row.flatten()
    }

    #[crate::sqlx_test]
    async fn records_current_target_and_is_idempotent(pool: PgPool) {
        let mac1: MacAddress = "02:00:00:00:00:01".parse().unwrap();
        let mac2: MacAddress = "02:00:00:00:00:02".parse().unwrap();
        let mut conn = pool.acquire().await.unwrap();

        // The backfill migration seeds the bmc site-wide target at version 0, so
        // a device recorded now converges at 0.
        record_device_converged(&mut conn, mac1, CredentialRotationType::Bmc)
            .await
            .unwrap();
        assert_eq!(
            version_of(&mut conn, "02:00:00:00:00:01", "bmc").await,
            Some(0)
        );

        // Bump the site-wide target. An already-recorded device must NOT be
        // clobbered -- the engine owns version transitions, not this hook.
        sqlx::query(
            "UPDATE sitewide_credential_rotation SET target_version = 3 \
             WHERE credential_type = 'bmc'",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        record_device_converged(&mut conn, mac1, CredentialRotationType::Bmc)
            .await
            .unwrap();
        assert_eq!(
            version_of(&mut conn, "02:00:00:00:00:01", "bmc").await,
            Some(0),
            "existing row must be preserved on re-ingestion"
        );

        // A device first seen after the bump records the current target (3).
        record_device_converged(&mut conn, mac2, CredentialRotationType::Bmc)
            .await
            .unwrap();
        assert_eq!(
            version_of(&mut conn, "02:00:00:00:00:02", "bmc").await,
            Some(3),
            "a newly ingested device records the current site-wide target"
        );

        // nvos has no site-wide target row (deliberately not backfilled, and its
        // only caller is gated off until REQ-6). Recording convergence for a
        // type with no site-wide target is a corrupted invariant, so the writer
        // fails loudly instead of guessing a version -- and writes nothing.
        let err = record_device_converged(&mut conn, mac1, CredentialRotationType::Nvos)
            .await
            .expect_err("nvos has no site-wide target row, so recording must fail");
        assert!(
            matches!(
                err,
                DatabaseError::MissingSitewideRotationTarget(CredentialRotationType::Nvos)
            ),
            "expected MissingSitewideRotationTarget for nvos, got: {err:?}"
        );
        assert_eq!(
            version_of(&mut conn, "02:00:00:00:00:01", "nvos").await,
            None,
            "a failed record must not write a row"
        );
    }

    #[crate::sqlx_test]
    async fn stages_and_promotes_rotation_ignoring_sitewide_target(pool: PgPool) {
        let mac: MacAddress = "02:00:00:00:00:0a".parse().unwrap();
        let mut conn = pool.acquire().await.unwrap();

        // Advance the site-wide lockdown target so it differs from the version we
        // stage. Promotion must land exactly the staged version (the one the card
        // was locked under), never the live target -- this is the TOCTOU the
        // two-phase lock flow guards against.
        sqlx::query(
            "UPDATE sitewide_credential_rotation SET target_version = 5 \
             WHERE credential_type = 'lockdown_ikm'",
        )
        .execute(&mut *conn)
        .await
        .unwrap();

        // Phase one (issue): stage the in-flight rotation. current_version stays
        // NULL ("not yet established") until the hardware confirms.
        mark_device_rotating_to_version(&mut conn, mac, CredentialRotationType::LockdownIkm, 2)
            .await
            .unwrap();
        assert_eq!(
            rotating_version_of(&mut conn, "02:00:00:00:00:0a", "lockdown_ikm").await,
            Some(2),
            "issue must stage the derived version as the in-flight marker"
        );
        assert_eq!(
            version_of(&mut conn, "02:00:00:00:00:0a", "lockdown_ikm").await,
            None,
            "current_version must not advance until the lock is confirmed"
        );

        // Phase two (confirm): promote the staged version to current and clear
        // the in-flight marker.
        let promoted =
            promote_rotating_to_current(&mut conn, mac, CredentialRotationType::LockdownIkm)
                .await
                .unwrap();
        assert!(promoted, "a staged rotation must report as promoted");
        assert_eq!(
            version_of(&mut conn, "02:00:00:00:00:0a", "lockdown_ikm").await,
            Some(2),
            "must promote the staged version (2), not the site-wide target (5)"
        );
        assert_eq!(
            rotating_version_of(&mut conn, "02:00:00:00:00:0a", "lockdown_ikm").await,
            None,
            "the in-flight marker must be cleared on promotion"
        );

        // Idempotent: a re-observed lock finds nothing staged, so it is a no-op
        // that leaves the promoted version intact.
        let promoted_again =
            promote_rotating_to_current(&mut conn, mac, CredentialRotationType::LockdownIkm)
                .await
                .unwrap();
        assert!(
            !promoted_again,
            "a second promotion with nothing staged must report no-op"
        );
        assert_eq!(
            version_of(&mut conn, "02:00:00:00:00:0a", "lockdown_ikm").await,
            Some(2),
            "current_version must be preserved when there is nothing to promote"
        );
    }

    #[crate::sqlx_test]
    async fn delete_removes_only_the_targeted_row_and_is_idempotent(pool: PgPool) {
        let mac: MacAddress = "02:00:00:00:00:01".parse().unwrap();
        let mut conn = pool.acquire().await.unwrap();

        record_device_converged(&mut conn, mac, CredentialRotationType::Bmc)
            .await
            .unwrap();
        record_device_converged(&mut conn, mac, CredentialRotationType::HostUefi)
            .await
            .unwrap();

        // Deleting one credential type leaves the device's other markers intact.
        delete_device_converged(&mut conn, mac, CredentialRotationType::Bmc)
            .await
            .unwrap();
        assert_eq!(
            version_of(&mut conn, "02:00:00:00:00:01", "bmc").await,
            None
        );
        assert_eq!(
            version_of(&mut conn, "02:00:00:00:00:01", "host_uefi").await,
            Some(0),
            "deleting bmc must not touch the host_uefi marker"
        );

        // Deleting a row that no longer exists is a no-op, not an error.
        delete_device_converged(&mut conn, mac, CredentialRotationType::Bmc)
            .await
            .unwrap();
    }
}
