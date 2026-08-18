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

//! Decides when a provisioning boot has finished.
//!
//! Serving a tenant's iPXE script proves only that the host asked for it. NICo
//! never sees the install itself, so [`evaluate`] infers the answer from the
//! signals it does have and bounds how long it will keep inferring.

use chrono::{DateTime, Duration, Utc};
use model::instance::snapshot::InstanceSnapshot;

/// Why an instance is considered provisioned.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum CompletionEvidence {
    /// The booted operating system contacted NICo's metadata service. The
    /// contact was cleared when the boot was armed, so this one is fresh.
    PhoneHome,
    /// The host stopped asking for iPXE instructions, which is what booting an
    /// installed operating system looks like from outside the host.
    HostWentQuiet,
}

/// Why an instance's provisioning boot is being given up on.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum ProvisioningFailure {
    /// The host asked for more attempts than its budget allows, which can only
    /// happen if every attempt before the last one failed.
    ServeBudgetExhausted,
    /// Neither success nor further attempts arrived before the deadline.
    DeadlineElapsed,
}

/// What to do with an instance awaiting evidence that provisioning finished.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(super) enum ProvisioningOutcome {
    /// A newer tenant request replaces this attempt; hand back to the
    /// `Assigned{Ready}` handler, which owns both reboot and deletion.
    Superseded,
    Complete(CompletionEvidence),
    /// Nothing to do. Each PXE request re-serves the script on its own, so
    /// waiting is how a failed install is retried.
    KeepWaiting,
    Failed(ProvisioningFailure),
}

/// Signals about one provisioning boot, read from the instance row.
#[derive(Copy, Clone, Debug)]
pub(super) struct ProvisioningSignals {
    /// A tenant asked for another custom-iPXE boot.
    pub(super) reboot_requested: bool,
    /// A tenant asked for the instance to be released.
    pub(super) deletion_requested: bool,
    /// The instance's operating system reports completion by phoning home.
    pub(super) phone_home_enabled: bool,
    /// A phone-home contact is recorded for this boot.
    pub(super) phone_home_contacted: bool,
    /// How many times the tenant's script has been served for this boot.
    pub(super) serve_count: u32,
    /// When it was last served, or `None` if the host never asked.
    pub(super) last_served_at: Option<DateTime<Utc>>,
    /// When the boot was armed.
    pub(super) started_at: DateTime<Utc>,
    /// When to give up without success evidence.
    pub(super) deadline: DateTime<Utc>,
}

impl ProvisioningSignals {
    pub(super) fn from_instance(
        instance: &InstanceSnapshot,
        started_at: DateTime<Utc>,
        deadline: DateTime<Utc>,
    ) -> Self {
        Self {
            reboot_requested: instance.custom_pxe_reboot_requested,
            deletion_requested: instance.deleted.is_some(),
            phone_home_enabled: instance.config.os.phone_home_enabled,
            phone_home_contacted: instance.observations.phone_home_last_contact.is_some(),
            serve_count: instance.custom_pxe_serve_count,
            last_served_at: instance.custom_pxe_last_served_at,
            started_at,
            deadline,
        }
    }
}

/// Site limits on how long completion may be inferred for.
#[derive(Copy, Clone, Debug)]
pub(super) struct ProvisioningBounds {
    /// How long without a serve implies the host booted its own disk. Only
    /// consulted for instances that do not phone home.
    pub(super) quiet_window: Duration,
    /// How many serves one provisioning boot may take.
    pub(super) max_serves: u32,
}

/// Classifies a provisioning boot from the signals recorded for it.
///
/// Success is checked before failure so an install that completed on its last
/// permitted attempt is not failed for having used the whole budget.
pub(super) fn evaluate(
    signals: ProvisioningSignals,
    bounds: ProvisioningBounds,
    now: DateTime<Utc>,
) -> ProvisioningOutcome {
    if signals.reboot_requested || signals.deletion_requested {
        return ProvisioningOutcome::Superseded;
    }

    if signals.phone_home_enabled {
        if signals.phone_home_contacted {
            return ProvisioningOutcome::Complete(CompletionEvidence::PhoneHome);
        }
    } else {
        // A host that never asked for instructions has been quiet since the
        // boot was armed. Silence cannot be told apart from a host that booted
        // a disk it already had, which is why phone home is the better signal
        // and this one is bounded by the deadline below.
        let quiet_since = signals.last_served_at.unwrap_or(signals.started_at);
        if now - quiet_since >= bounds.quiet_window {
            return ProvisioningOutcome::Complete(CompletionEvidence::HostWentQuiet);
        }
    }

    if signals.serve_count > bounds.max_serves {
        return ProvisioningOutcome::Failed(ProvisioningFailure::ServeBudgetExhausted);
    }
    if now >= signals.deadline {
        return ProvisioningOutcome::Failed(ProvisioningFailure::DeadlineElapsed);
    }

    ProvisioningOutcome::KeepWaiting
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

    use super::*;

    fn timestamp() -> DateTime<Utc> {
        DateTime::from_timestamp(1_722_000_000, 0).expect("fixture timestamp")
    }

    /// Every combination of the signals that decide one provisioning boot.
    ///
    /// Ages are relative to `now`: `served_ago`/`started_ago` count backwards
    /// from it, and `deadline_in` forwards, so a non-positive `deadline_in`
    /// means the deadline has passed.
    #[test]
    fn provisioning_outcome_follows_the_recorded_signals() {
        struct Input {
            reboot_requested: bool,
            deletion_requested: bool,
            phone_home_enabled: bool,
            phone_home_contacted: bool,
            serve_count: u32,
            served_ago: Option<Duration>,
            started_ago: Duration,
            deadline_in: Duration,
        }

        /// One serve, recent enough that the quiet window has not elapsed, with
        /// budget and deadline to spare: on its own this waits.
        fn in_flight() -> Input {
            Input {
                reboot_requested: false,
                deletion_requested: false,
                phone_home_enabled: false,
                phone_home_contacted: false,
                serve_count: 1,
                served_ago: Some(Duration::minutes(1)),
                started_ago: Duration::minutes(2),
                deadline_in: Duration::minutes(30),
            }
        }

        let now = timestamp();
        let bounds = ProvisioningBounds {
            quiet_window: Duration::minutes(15),
            max_serves: 4,
        };

        value_scenarios!(
            run = |input: Input| {
                let signals = ProvisioningSignals {
                    reboot_requested: input.reboot_requested,
                    deletion_requested: input.deletion_requested,
                    phone_home_enabled: input.phone_home_enabled,
                    phone_home_contacted: input.phone_home_contacted,
                    serve_count: input.serve_count,
                    last_served_at: input.served_ago.map(|age| now - age),
                    started_at: now - input.started_ago,
                    deadline: now + input.deadline_in,
                };
                evaluate(signals, bounds, now)
            };
            "a newer tenant request wins over every other signal" {
                Input { reboot_requested: true, ..in_flight() }
                    => ProvisioningOutcome::Superseded,
                Input { deletion_requested: true, ..in_flight() }
                    => ProvisioningOutcome::Superseded,
                // Even from a state that would otherwise fail, so an operator
                // can retry instead of waiting for the attempt to time out.
                Input { reboot_requested: true, serve_count: 99, deadline_in: -Duration::minutes(1), ..in_flight() }
                    => ProvisioningOutcome::Superseded,
            }
            "a phone-home contact completes the boot" {
                Input { phone_home_enabled: true, phone_home_contacted: true, ..in_flight() }
                    => ProvisioningOutcome::Complete(CompletionEvidence::PhoneHome),
                // The last permitted attempt is the one that installed.
                Input { phone_home_enabled: true, phone_home_contacted: true, serve_count: 99, ..in_flight() }
                    => ProvisioningOutcome::Complete(CompletionEvidence::PhoneHome),
            }
            "an instance enrolled in phone home waits for that contact alone" {
                // Quiet for far longer than the window, which would complete a
                // non-enrolled instance, proves nothing here: the OS is
                // supposed to say so itself.
                Input { phone_home_enabled: true, served_ago: Some(Duration::hours(10)), ..in_flight() }
                    => ProvisioningOutcome::KeepWaiting,
            }
            "silence completes a boot that has no phone home to wait for" {
                Input { served_ago: Some(bounds.quiet_window), ..in_flight() }
                    => ProvisioningOutcome::Complete(CompletionEvidence::HostWentQuiet),
                // A host that never asked for instructions is measured from
                // when the boot was armed.
                Input { served_ago: None, serve_count: 0, started_ago: bounds.quiet_window, ..in_flight() }
                    => ProvisioningOutcome::Complete(CompletionEvidence::HostWentQuiet),
                // A contact recorded by an instance that does not report
                // completion that way is not evidence of anything.
                Input { phone_home_contacted: true, ..in_flight() }
                    => ProvisioningOutcome::KeepWaiting,
                Input { served_ago: Some(bounds.quiet_window - Duration::seconds(1)), ..in_flight() }
                    => ProvisioningOutcome::KeepWaiting,
                Input { served_ago: None, serve_count: 0, started_ago: bounds.quiet_window - Duration::seconds(1), ..in_flight() }
                    => ProvisioningOutcome::KeepWaiting,
            }
            "a host that keeps asking for the script has run out of attempts" {
                Input { serve_count: bounds.max_serves + 1, ..in_flight() }
                    => ProvisioningOutcome::Failed(ProvisioningFailure::ServeBudgetExhausted),
                // Spending the budget is not itself a failure; the attempt it
                // paid for still gets its window.
                Input { serve_count: bounds.max_serves, ..in_flight() }
                    => ProvisioningOutcome::KeepWaiting,
            }
            "the deadline ends a boot that produced neither success nor attempts" {
                Input { deadline_in: Duration::zero(), phone_home_enabled: true, ..in_flight() }
                    => ProvisioningOutcome::Failed(ProvisioningFailure::DeadlineElapsed),
                Input { deadline_in: -Duration::hours(1), phone_home_enabled: true, ..in_flight() }
                    => ProvisioningOutcome::Failed(ProvisioningFailure::DeadlineElapsed),
                // An exhausted budget is reported ahead of the deadline: it
                // says why the boot failed, where the deadline only says when.
                Input { serve_count: bounds.max_serves + 1, deadline_in: -Duration::hours(1), phone_home_enabled: true, ..in_flight() }
                    => ProvisioningOutcome::Failed(ProvisioningFailure::ServeBudgetExhausted),
                Input { deadline_in: Duration::seconds(1), phone_home_enabled: true, ..in_flight() }
                    => ProvisioningOutcome::KeepWaiting,
            }
        );
    }
}
