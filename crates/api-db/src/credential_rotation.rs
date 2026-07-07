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

use chrono::{DateTime, Utc};
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

/// The current site-wide rotation target for `credential_type`, or `None` if no
/// target row exists. Every credential type the backfill seeds (everything but
/// `nvos`) has a row, so `None` means the type is not yet under management.
///
/// `RotateCredential` reads this to learn the version it must write the
/// rotate-TO secret at (`current + 1`) before publishing the new target with
/// [`set_next_target_version`].
pub async fn current_target_version(
    conn: &mut PgConnection,
    credential_type: CredentialRotationType,
) -> Result<Option<i32>, DatabaseError> {
    let query = "SELECT target_version FROM sitewide_credential_rotation \
                 WHERE credential_type = $1";
    sqlx::query_scalar::<_, i32>(query)
        .bind(credential_type)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// A site-wide rotation target after it has been advanced by
/// [`set_next_target_version`].
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct StagedRotation {
    pub target_version: i32,
    pub started_at: DateTime<Utc>,
}

/// Atomically advances the site-wide rotation target for `credential_type` from
/// `expected_current` to `expected_current + 1`, stamping `started_at = now()`
/// and recording `request_meta`.
///
/// This is a compare-and-set on `target_version`: it returns the new
/// [`StagedRotation`] on success, or `None` if no row matched `expected_current`
/// -- either another rotation advanced the target first, or the row is missing.
///
/// The handler writes the rotate-TO secret at the predicted next version
/// *before* calling this, so publishing the target last guarantees a device is
/// never recorded as converged to a version whose secret has not been written
/// yet. The model is table-driven: the current site-wide credential is whichever
/// version this `target_version` names, so the bump alone makes the new version
/// current (no unversioned alias is maintained). A `None` return means the
/// caller lost the race and must retry against the new target rather than assume
/// success.
pub async fn set_next_target_version(
    conn: &mut PgConnection,
    credential_type: CredentialRotationType,
    expected_current: i32,
    request_meta: serde_json::Value,
) -> Result<Option<StagedRotation>, DatabaseError> {
    let query = "UPDATE sitewide_credential_rotation \
                 SET target_version = target_version + 1, \
                     started_at = now(), \
                     request_meta = $3 \
                 WHERE credential_type = $1 AND target_version = $2 \
                 RETURNING target_version, started_at";
    sqlx::query_as::<_, StagedRotation>(query)
        .bind(credential_type)
        .bind(expected_current)
        .bind(request_meta)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Aggregate convergence status for a site-wide rotation: how many devices have
/// reached the current target, how many are still pending, and how many are
/// quarantined (plus the quarantined MACs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationStatus {
    pub target_version: i32,
    pub converged: i64,
    pub pending: i64,
    pub quarantined: i64,
    pub quarantined_device_macs: Vec<String>,
    pub started_at: DateTime<Utc>,
}

/// Just the counted columns; the quarantined MAC list is gathered separately so
/// the aggregate stays a single grouped row.
#[derive(sqlx::FromRow)]
struct RotationCounts {
    target_version: i32,
    converged: i64,
    pending: i64,
    quarantined: i64,
    started_at: DateTime<Utc>,
}

/// Convergence status for `credential_type`'s current site-wide target.
///
/// A device counts as `converged` once its `current_version` reaches the target,
/// `quarantined` while its backoff window is in the future, and `pending`
/// otherwise (including "not yet established", `current_version IS NULL`).
/// Errors with [`DatabaseError::MissingSitewideRotationTarget`] when no target
/// row exists (e.g. `nvos`, which is not backfilled).
pub async fn rotation_status(
    conn: &mut PgConnection,
    credential_type: CredentialRotationType,
) -> Result<RotationStatus, DatabaseError> {
    // count(d.device_mac) ignores the synthetic all-NULL row a LEFT JOIN
    // produces when a type has zero devices, so every bucket is 0 in that case
    // while the site-wide row still yields target_version / started_at.
    let counts_query = "SELECT s.target_version, \
                            count(d.device_mac) FILTER ( \
                                WHERE d.current_version >= s.target_version) AS converged, \
                            count(d.device_mac) FILTER ( \
                                WHERE (d.current_version IS NULL \
                                       OR d.current_version < s.target_version) \
                                  AND (d.rotate_quarantined_until IS NULL \
                                       OR d.rotate_quarantined_until <= now())) AS pending, \
                            count(d.device_mac) FILTER ( \
                                WHERE d.rotate_quarantined_until > now()) AS quarantined, \
                            s.started_at \
                        FROM sitewide_credential_rotation s \
                        LEFT JOIN device_credential_rotation d \
                            ON d.credential_type = s.credential_type \
                        WHERE s.credential_type = $1 \
                        GROUP BY s.target_version, s.started_at";
    let counts = sqlx::query_as::<_, RotationCounts>(counts_query)
        .bind(credential_type)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| DatabaseError::query(counts_query, e))?
        .ok_or(DatabaseError::MissingSitewideRotationTarget(
            credential_type,
        ))?;

    let macs_query = "SELECT device_mac::text FROM device_credential_rotation \
                      WHERE credential_type = $1 AND rotate_quarantined_until > now() \
                      ORDER BY device_mac";
    let quarantined_device_macs = sqlx::query_scalar::<_, String>(macs_query)
        .bind(credential_type)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| DatabaseError::query(macs_query, e))?;

    Ok(RotationStatus {
        target_version: counts.target_version,
        converged: counts.converged,
        pending: counts.pending,
        quarantined: counts.quarantined,
        quarantined_device_macs,
        started_at: counts.started_at,
    })
}

/// Per-device convergence detail for `credential_type`'s current site-wide
/// target. The `converged` / `quarantined` flags are evaluated server-side
/// against the same `now()` the aggregate [`rotation_status`] uses, so a single
/// device's status is consistent with the site-wide counts.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DeviceRotationStatus {
    /// Site-wide target this device is converging to (from the sitewide row).
    pub target_version: i32,
    /// When the current site-wide target was staged.
    pub started_at: DateTime<Utc>,
    pub device_mac: String,
    /// Version live on the hardware; `None` means "not yet established".
    pub current_version: Option<i32>,
    /// Non-`None` while a rotation is mid-flight on this device.
    pub rotating_to_version: Option<i32>,
    /// `current_version >= target_version` (false when `current_version` is NULL).
    pub converged: bool,
    /// In a backoff window (`rotate_quarantined_until > now()`).
    pub quarantined: bool,
    pub quarantined_until: Option<DateTime<Utc>>,
    pub rotate_attempts: i32,
    pub rotate_last_attempt_at: Option<DateTime<Utc>>,
    pub rotate_last_error_redacted: Option<String>,
}

/// Convergence status for a single device's `credential_type` credential.
///
/// Returns `None` when no `device_credential_rotation` row exists for the
/// `(device_mac, credential_type)` pair -- the caller surfaces that as
/// `NotFound` rather than fabricating a "not established" status for a device
/// NICo has no record of (e.g. a mistyped MAC). The inner JOIN to
/// `sitewide_credential_rotation` means a credential type with no target row
/// (e.g. `nvos`, never backfilled) also yields `None`, but the handler rejects
/// those before reaching here.
pub async fn device_rotation_status(
    conn: &mut PgConnection,
    credential_type: CredentialRotationType,
    device_mac: MacAddress,
) -> Result<Option<DeviceRotationStatus>, DatabaseError> {
    // COALESCE guards the two derived booleans: `current_version >= target` is
    // NULL when current_version is NULL ("not yet established"), and the
    // quarantine comparison is NULL when the window is unset -- both mean false.
    let query = "SELECT s.target_version, \
                        s.started_at, \
                        d.device_mac::text AS device_mac, \
                        d.current_version, \
                        d.rotating_to_version, \
                        COALESCE(d.current_version >= s.target_version, false) AS converged, \
                        COALESCE(d.rotate_quarantined_until > now(), false) AS quarantined, \
                        d.rotate_quarantined_until AS quarantined_until, \
                        d.rotate_attempts, \
                        d.rotate_last_attempt_at, \
                        d.rotate_last_error_redacted \
                 FROM sitewide_credential_rotation s \
                 JOIN device_credential_rotation d \
                     ON d.credential_type = s.credential_type \
                 WHERE s.credential_type = $1 AND d.device_mac = $2";
    sqlx::query_as::<_, DeviceRotationStatus>(query)
        .bind(credential_type)
        .bind(device_mac)
        .fetch_optional(&mut *conn)
        .await
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
        CredentialRotationType, current_target_version, delete_device_converged,
        device_rotation_status, mark_device_rotating_to_version, promote_rotating_to_current,
        record_device_converged, rotation_status, set_next_target_version,
    };
    use crate::DatabaseError;

    // Inserts a device convergence row with an explicit current_version (and no
    // quarantine) for the status-counting tests.
    async fn insert_device(conn: &mut PgConnection, mac: &str, ctype: &str, current: Option<i32>) {
        sqlx::query(
            "INSERT INTO device_credential_rotation \
                 (device_mac, credential_type, current_version) \
             VALUES ($1::macaddr, $2::credential_rotation_type, $3)",
        )
        .bind(mac)
        .bind(ctype)
        .bind(current)
        .execute(&mut *conn)
        .await
        .unwrap();
    }

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

    #[crate::sqlx_test]
    async fn set_next_target_version_advances_and_detects_races(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();

        // bmc is seeded at target 0 by the backfill. Advancing from the current
        // target succeeds and returns the new version.
        let staged = set_next_target_version(
            &mut conn,
            CredentialRotationType::Bmc,
            0,
            serde_json::json!({"reason": "first"}),
        )
        .await
        .unwrap()
        .expect("advancing from the current target must succeed");
        assert_eq!(staged.target_version, 1);

        // Supersede: advancing from the new current (1) goes to 2 and re-stamps
        // started_at.
        let staged_again = set_next_target_version(
            &mut conn,
            CredentialRotationType::Bmc,
            1,
            serde_json::json!({"reason": "second"}),
        )
        .await
        .unwrap()
        .expect("advancing from the new current target must succeed");
        assert_eq!(staged_again.target_version, 2);
        assert!(staged_again.started_at >= staged.started_at);

        // A stale expected_current (0) no longer matches the row -- a concurrent
        // rotation already advanced it -- so the CAS makes no change and reports
        // the race via None.
        let stale = set_next_target_version(
            &mut conn,
            CredentialRotationType::Bmc,
            0,
            serde_json::json!({}),
        )
        .await
        .unwrap();
        assert!(
            stale.is_none(),
            "a stale expected version must not advance the target"
        );
        assert_eq!(
            current_target_version(&mut conn, CredentialRotationType::Bmc)
                .await
                .unwrap(),
            Some(2),
            "the failed CAS must leave the target unchanged"
        );
    }

    #[crate::sqlx_test]
    async fn rotation_status_counts_converged_pending_and_quarantined(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();

        // Advance host_uefi to target 1 so devices can sit on either side of it.
        set_next_target_version(
            &mut conn,
            CredentialRotationType::HostUefi,
            0,
            serde_json::json!({}),
        )
        .await
        .unwrap()
        .unwrap();

        // converged: current_version >= target (1).
        insert_device(&mut conn, "02:00:00:00:00:01", "host_uefi", Some(1)).await;
        // pending: behind the target.
        insert_device(&mut conn, "02:00:00:00:00:02", "host_uefi", Some(0)).await;
        // pending: not yet established (NULL current_version).
        insert_device(&mut conn, "02:00:00:00:00:03", "host_uefi", None).await;
        // quarantined: behind the target but with a future backoff window, so it
        // is counted as quarantined rather than pending.
        sqlx::query(
            "INSERT INTO device_credential_rotation \
                 (device_mac, credential_type, current_version, rotate_quarantined_until) \
             VALUES ('02:00:00:00:00:04'::macaddr, 'host_uefi', 0, now() + interval '1 hour')",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        // A different credential type must not leak into the host_uefi counts.
        insert_device(&mut conn, "02:00:00:00:00:05", "bmc", Some(0)).await;

        let status = rotation_status(&mut conn, CredentialRotationType::HostUefi)
            .await
            .unwrap();
        assert_eq!(status.target_version, 1);
        assert_eq!(status.converged, 1);
        assert_eq!(status.pending, 2);
        assert_eq!(status.quarantined, 1);
        assert_eq!(
            status.quarantined_device_macs,
            vec!["02:00:00:00:00:04".to_string()]
        );

        // A type with no devices reports zero everywhere but still surfaces the
        // site-wide target/started_at (the LEFT JOIN's synthetic row is ignored).
        let empty = rotation_status(&mut conn, CredentialRotationType::DpuUefi)
            .await
            .unwrap();
        assert_eq!(empty.target_version, 0);
        assert_eq!(empty.converged, 0);
        assert_eq!(empty.pending, 0);
        assert_eq!(empty.quarantined, 0);
        assert!(empty.quarantined_device_macs.is_empty());

        // nvos has no site-wide target row, so status fails loudly rather than
        // fabricating an empty rotation.
        let err = rotation_status(&mut conn, CredentialRotationType::Nvos)
            .await
            .expect_err("nvos has no site-wide target row");
        assert!(matches!(
            err,
            DatabaseError::MissingSitewideRotationTarget(CredentialRotationType::Nvos)
        ));
    }

    #[crate::sqlx_test]
    async fn device_rotation_status_reports_one_device(pool: PgPool) {
        let mut conn = pool.acquire().await.unwrap();

        // Advance host_uefi to target 1 so devices can sit on either side of it.
        set_next_target_version(
            &mut conn,
            CredentialRotationType::HostUefi,
            0,
            serde_json::json!({}),
        )
        .await
        .unwrap()
        .unwrap();

        // Converged: current_version >= target (1).
        insert_device(&mut conn, "02:00:00:00:00:01", "host_uefi", Some(1)).await;
        let converged = device_rotation_status(
            &mut conn,
            CredentialRotationType::HostUefi,
            "02:00:00:00:00:01".parse().unwrap(),
        )
        .await
        .unwrap()
        .expect("a recorded device must have a status");
        assert_eq!(converged.target_version, 1);
        assert_eq!(converged.current_version, Some(1));
        assert!(converged.converged);
        assert!(!converged.quarantined);
        assert_eq!(converged.device_mac, "02:00:00:00:00:01");

        // Pending: behind the target, no backoff window.
        insert_device(&mut conn, "02:00:00:00:00:02", "host_uefi", Some(0)).await;
        let pending = device_rotation_status(
            &mut conn,
            CredentialRotationType::HostUefi,
            "02:00:00:00:00:02".parse().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!pending.converged);
        assert!(!pending.quarantined);

        // Not yet established: NULL current_version is not converged.
        insert_device(&mut conn, "02:00:00:00:00:03", "host_uefi", None).await;
        let unestablished = device_rotation_status(
            &mut conn,
            CredentialRotationType::HostUefi,
            "02:00:00:00:00:03".parse().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(unestablished.current_version, None);
        assert!(!unestablished.converged);

        // Quarantined: behind the target with a future backoff window.
        sqlx::query(
            "INSERT INTO device_credential_rotation \
                 (device_mac, credential_type, current_version, rotate_quarantined_until, \
                  rotate_attempts, rotate_last_error_redacted) \
             VALUES ('02:00:00:00:00:04'::macaddr, 'host_uefi', 0, now() + interval '1 hour', \
                     3, 'redacted boom')",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        let quarantined = device_rotation_status(
            &mut conn,
            CredentialRotationType::HostUefi,
            "02:00:00:00:00:04".parse().unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!quarantined.converged);
        assert!(quarantined.quarantined);
        assert!(quarantined.quarantined_until.is_some());
        assert_eq!(quarantined.rotate_attempts, 3);
        assert_eq!(
            quarantined.rotate_last_error_redacted.as_deref(),
            Some("redacted boom")
        );

        // An unknown MAC has no row, so the per-device status is None (the
        // handler maps that to NotFound rather than guessing a state).
        let missing = device_rotation_status(
            &mut conn,
            CredentialRotationType::HostUefi,
            "02:00:00:00:00:ff".parse().unwrap(),
        )
        .await
        .unwrap();
        assert!(missing.is_none(), "an unknown MAC must yield no status");
    }
}
