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

//! Rack Validation helper types

use std::collections::HashMap;

use model::machine::Machine;
use model::metadata::Metadata;
use model::rack::MachineRvLabels;

use crate::state_controller::state_handler::StateHandlerError;

//------------------------------------------------------------------------------

/// Aggregated summary of all partition validation statuses in a rack.
/// Used by the state handler to determine state transitions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RackPartitionSummary {
    /// Total number of partitions in the rack
    /// TODO: make sure all fields below sums together to total
    pub total_partitions: usize,
    /// Number of partitions that haven't started validation
    pub pending: usize,
    /// Number of partitions currently being validated
    pub in_progress: usize,
    /// Number of partitions that passed validation
    pub validated: usize,
    /// Number of partitions that failed validation
    pub failed: usize,
}

/// Per-machine rack-validation state, derived from machine metadata labels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MachineRvState {
    Idle,
    Inp,
    Pass,
    Fail(String),
}

impl TryFrom<Metadata> for MachineRvState {
    type Error = StateHandlerError;

    fn try_from(metadata: Metadata) -> Result<Self, Self::Error> {
        let st_label = MachineRvLabels::State.as_str();
        let fail_label = MachineRvLabels::FailDesc.as_str();

        let st = metadata
            .labels
            .get(st_label)
            .ok_or_else(|| {
                StateHandlerError::InvalidState(format!("missing required label '{}'", st_label))
            })?
            .as_str();

        match st {
            "idle" => Ok(MachineRvState::Idle),
            "inp" => Ok(MachineRvState::Inp),
            "pass" => Ok(MachineRvState::Pass),
            "fail" => {
                let desc = metadata.labels.get(fail_label).cloned().unwrap_or_default();
                Ok(MachineRvState::Fail(desc))
            }
            other => Err(StateHandlerError::InvalidState(format!(
                "unknown '{}' value: '{}'",
                st_label, other
            ))),
        }
    }
}

//------------------------------------------------------------------------------

/// Partition grouping: maps partition ID -> per-node validation states.
///
/// Only machines that carry the `rv.part-id` label are considered
/// validation participants. Machines without it are silently skipped.
/// When a `validation_run_id` is provided, machines whose `rv.run-id`
/// doesn't match are also skipped (stale labels from previous runs).
pub struct RvPartitions {
    inner: HashMap<String, Vec<MachineRvState>>,
}

impl RvPartitions {
    /// Build from a vec of machines, optionally filtering by run ID.
    pub fn from_machines(
        machines: Vec<Machine>,
        validation_run_id: Option<String>,
    ) -> Result<Self, StateHandlerError> {
        Self::from_meta_iter(machines.into_iter().map(|m| m.metadata), validation_run_id)
    }

    /// Core grouping logic over any iterator of Metadata.
    /// Extracted so unit tests can feed plain metadata without constructing
    /// full Machine values.
    pub fn from_meta_iter(
        iter: impl Iterator<Item = Metadata>,
        validation_run_id: Option<String>,
    ) -> Result<Self, StateHandlerError> {
        let mut inner: HashMap<String, Vec<MachineRvState>> = HashMap::new();
        let part_label = MachineRvLabels::PartitionId.as_str();
        let run_label = MachineRvLabels::RunId.as_str();

        for mut meta in iter {
            // Skip machines that aren't part of rack validation
            let Some(part_id) = meta.labels.remove(part_label) else {
                continue;
            };

            // Skip machines whose run ID doesn't match the current run

            let run_id = meta.labels.remove(run_label);
            let run_id_curr = validation_run_id.as_ref();

            if let Some(expected) = run_id_curr {
                // In case we are expecting run-id, we need to reject nodes that
                // aren't fitting in.

                let Some(fetched) = run_id else {
                    // No need to grab nodes if they don't have run-id set in the
                    // machine metadata.
                    continue;
                };

                if *expected != fetched {
                    // No need to grab nodes if their run-id is not what we
                    // expect here.
                    continue;
                }
            }

            let rv_state = meta.try_into()?;
            inner.entry(part_id).or_default().push(rv_state);
        }

        Ok(RvPartitions { inner })
    }

    /// Aggregate per-node states into a [`RackPartitionSummary`].
    ///
    /// For each partition, the aggregate status is:
    /// - Validated   if all nodes are `Pass`
    /// - Failed      else if any node is `Fail`
    /// - InProgress  else if any node is `Inp`
    /// - Pending     otherwise (all `Idle`, or a mix of `Idle`/`Pass`)
    pub fn summarize(&self) -> RackPartitionSummary {
        let mut summary = RackPartitionSummary {
            total_partitions: self.inner.len(),
            ..Default::default()
        };

        for states in self.inner.values() {
            // Order of checks matter

            if states.iter().all(|s| *s == MachineRvState::Pass) {
                summary.validated += 1;
            } else if states.iter().any(|s| matches!(s, MachineRvState::Fail(_))) {
                summary.failed += 1;
            } else if states.contains(&MachineRvState::Inp) {
                summary.in_progress += 1;
            } else {
                summary.pending += 1;
            }
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    // -------------------------------------------------------------------------
    // RV state inference tests

    /// Helper: build a Metadata with given label pairs.
    fn metadata_with_labels(pairs: &[(&str, &str)]) -> Metadata {
        Metadata {
            name: String::new(),
            description: String::new(),
            labels: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn test_machine_rv_state_from_metadata() {
        // All four valid statuses
        let m = metadata_with_labels(&[("rv.st", "idle"), ("rv.part-id", "p0")]);
        let s: MachineRvState = m.try_into().unwrap();
        assert_eq!(s, MachineRvState::Idle);

        let m = metadata_with_labels(&[("rv.st", "inp")]);
        let s: MachineRvState = m.try_into().unwrap();
        assert_eq!(s, MachineRvState::Inp);

        let m = metadata_with_labels(&[("rv.st", "pass")]);
        let s: MachineRvState = m.try_into().unwrap();
        assert_eq!(s, MachineRvState::Pass);

        // Fail without description
        let m = metadata_with_labels(&[("rv.st", "fail")]);
        let s: MachineRvState = m.try_into().unwrap();
        assert_eq!(s, MachineRvState::Fail(String::new()));

        // Fail with description
        let m = metadata_with_labels(&[("rv.st", "fail"), ("rv.fail-desc", "nccl-timeout")]);
        let s: MachineRvState = m.try_into().unwrap();
        assert_eq!(s, MachineRvState::Fail("nccl-timeout".into()));

        // Missing rv.st label
        let m = metadata_with_labels(&[("rv.part-id", "p0")]);
        let s: Result<MachineRvState, StateHandlerError> = m.try_into();
        assert!(matches!(
            s,
            Err(StateHandlerError::InvalidState(msg)) if msg.contains("missing")
        ));

        // Unknown status value
        let m = metadata_with_labels(&[("rv.st", "bogus")]);
        let s: Result<MachineRvState, StateHandlerError> = m.try_into();
        assert!(matches!(
            s,
            Err(StateHandlerError::InvalidState(msg)) if msg.contains("bogus")
        ));
    }

    // -----------------------------------------------------------------
    // RvPartitions tests

    #[test]
    fn test_partitions_from_meta_iter() {
        let metas = [
            metadata_with_labels(&[("rv.part-id", "p0"), ("rv.st", "pass")]),
            metadata_with_labels(&[("rv.part-id", "p0"), ("rv.st", "inp")]),
            metadata_with_labels(&[("rv.part-id", "p1"), ("rv.st", "idle")]),
            // No rv.part-id -> should be skipped
            metadata_with_labels(&[("some-other", "label")]),
        ];

        let parts = RvPartitions::from_meta_iter(metas.iter().cloned(), None).unwrap();

        assert_eq!(parts.inner.len(), 2);
        assert_eq!(parts.inner["p0"].len(), 2);
        assert_eq!(parts.inner["p0"][0], MachineRvState::Pass);
        assert_eq!(parts.inner["p0"][1], MachineRvState::Inp);
        assert_eq!(parts.inner["p1"].len(), 1);
        assert_eq!(parts.inner["p1"][0], MachineRvState::Idle);
    }

    #[test]
    fn test_partitions_run_id_filtering() {
        let metas = [
            // Current run -- should be included
            metadata_with_labels(&[
                ("rv.part-id", "p0"),
                ("rv.st", "pass"),
                ("rv.run-id", "run-005"),
            ]),
            // Stale run -- should be skipped
            metadata_with_labels(&[
                ("rv.part-id", "p0"),
                ("rv.st", "pass"),
                ("rv.run-id", "run-004"),
            ]),
            // No run ID -- should be skipped when filtering is active
            metadata_with_labels(&[("rv.part-id", "p1"), ("rv.st", "idle")]),
        ];

        let parts =
            RvPartitions::from_meta_iter(metas.iter().cloned(), Some("run-005".into())).unwrap();

        assert_eq!(parts.inner.len(), 1);
        assert_eq!(parts.inner["p0"].len(), 1);
        assert_eq!(parts.inner["p0"][0], MachineRvState::Pass);
    }

    #[test]
    fn test_partitions_no_run_id_accepts_all() {
        let metas = [
            metadata_with_labels(&[
                ("rv.part-id", "p0"),
                ("rv.st", "pass"),
                ("rv.run-id", "run-004"),
            ]),
            metadata_with_labels(&[("rv.part-id", "p1"), ("rv.st", "idle")]),
        ];

        // No run ID filtering -- all partitions included
        let parts = RvPartitions::from_meta_iter(metas.iter().cloned(), None).unwrap();

        assert_eq!(parts.inner.len(), 2);
    }

    #[test]
    fn test_partitions_summarize() {
        let metas = [
            // Partition p0: one node pass, one node fail -> Failed
            metadata_with_labels(&[("rv.part-id", "p0"), ("rv.st", "pass")]),
            metadata_with_labels(&[
                ("rv.part-id", "p0"),
                ("rv.st", "fail"),
                ("rv.fail-desc", "nccl"),
            ]),
            // Partition p1: all nodes pass -> Validated
            metadata_with_labels(&[("rv.part-id", "p1"), ("rv.st", "pass")]),
            metadata_with_labels(&[("rv.part-id", "p1"), ("rv.st", "pass")]),
            // Partition p2: one node is idle, one is inp -> InProgress
            metadata_with_labels(&[("rv.part-id", "p2"), ("rv.st", "idle")]),
            metadata_with_labels(&[("rv.part-id", "p2"), ("rv.st", "inp")]),
            // Partition p3: all nodes idle -> Pending
            metadata_with_labels(&[("rv.part-id", "p3"), ("rv.st", "idle")]),
        ];

        let parts = RvPartitions::from_meta_iter(metas.iter().cloned(), None).unwrap();
        let summary = parts.summarize();

        assert_eq!(summary.total_partitions, 4);
        assert_eq!(summary.failed, 1); // p0
        assert_eq!(summary.validated, 1); // p1
        assert_eq!(summary.in_progress, 1); // p2
        assert_eq!(summary.pending, 1); // p3
    }
}
