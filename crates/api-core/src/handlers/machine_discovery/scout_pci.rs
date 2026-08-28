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

use std::collections::HashSet;

use carbide_instrument::{DynamicLog, Event, LabelValue, LogAt};
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use mac_address::MacAddress;
use model::hardware_info::HardwareInfo;
use model::machine::Machine;
use model::machine_boot_interface::BootInterfaceSelectionSource;
use model::network_segment::NetworkSegmentType;
use rpc::forge::BootInterfaceSelectionSource as RpcBootInterfaceSelectionSource;

/// Bounded outcomes recorded for each Scout PCI evaluation.
#[derive(Clone, Copy, Debug, Eq, LabelValue, PartialEq)]
enum EvaluationResult {
    /// The Scout candidate matches the stored boot interface.
    Agreement,
    /// The Scout candidate differs from the stored boot interface.
    Disagreement,
    /// The report or stored selection is missing required information.
    Incomplete,
    /// The stored interfaces or report do not identify one candidate.
    Ambiguous,
}

/// The stored identity fields needed to match and describe one candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EligibleInterface {
    machine_interface_id: MachineInterfaceId,
    mac_address: MacAddress,
    dpu_machine_id: MachineId,
}

/// One eligible interface paired with its normalized Scout PCI slot.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Candidate {
    interface: EligibleInterface,
    pci_slot: String,
}

impl Candidate {
    /// Converts this candidate to the context attached to an evaluation.
    fn subject(&self) -> EvaluationSubject {
        EvaluationSubject {
            mac_address: self.interface.mac_address,
            pci_slot: Some(self.pci_slot.clone()),
        }
    }
}

/// Interface and slot details that explain which evidence produced a result.
#[derive(Clone, Debug, Eq, PartialEq)]
struct EvaluationSubject {
    mac_address: MacAddress,
    pci_slot: Option<String>,
}

impl EvaluationSubject {
    /// Builds context for an interface before its PCI slot is available.
    fn for_interface(interface: EligibleInterface) -> Self {
        Self {
            mac_address: interface.mac_address,
            pci_slot: None,
        }
    }
}

/// A Scout PCI result with no side effects that is emitted after discovery commits.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Evaluation {
    result: EvaluationResult,
    subject: Option<EvaluationSubject>,
    desired_mac_address: Option<MacAddress>,
    selection_source: Option<BootInterfaceSelectionSource>,
    reason: &'static str,
}

impl Evaluation {
    /// Captures a result and its stored machine context without emitting it.
    fn from_machine(
        machine: &Machine,
        result: EvaluationResult,
        subject: Option<EvaluationSubject>,
        reason: &'static str,
    ) -> Self {
        Self {
            result,
            subject,
            desired_mac_address: machine
                .config
                .desired_boot_interface
                .as_ref()
                .map(|target| target.value.mac_address()),
            selection_source: machine
                .config
                .boot_interface_selection
                .map(|selection| selection.source),
            reason,
        }
    }

    /// Emits the evaluation metric and its diagnostic log.
    pub(super) fn emit(self, machine_id: &MachineId) {
        let (interface_mac_address, pci_slot) = self.subject.map_or_else(
            || (None, None),
            |subject| (Some(subject.mac_address.to_string()), subject.pci_slot),
        );

        carbide_instrument::emit(ScoutPciEvaluated {
            result: self.result,
            machine_id: machine_id.to_string(),
            interface_mac_address,
            desired_mac_address: self
                .desired_mac_address
                .map(|mac_address| mac_address.to_string()),
            pci_slot,
            selection_source: self
                .selection_source
                .map(RpcBootInterfaceSelectionSource::from)
                .map(|selection_source| selection_source.as_str().to_owned()),
            reason: self.reason,
        });
    }
}

/// Metric and diagnostic record for one completed Scout PCI evaluation.
#[derive(Event)]
#[event(
    event_name = "scout_pci_evaluated",
    metric_name = "carbide_scout_pci_evaluations_total",
    component = "nico-api",
    log = dynamic,
    metric = counter,
    message = "Evaluated Scout PCI boot interface evidence",
    describe = "Number of comparisons between PCI slots reported by Scout and the stored boot interface, by result."
)]
struct ScoutPciEvaluated {
    #[label]
    result: EvaluationResult,
    #[context]
    machine_id: String,
    #[context]
    interface_mac_address: Option<String>,
    #[context]
    desired_mac_address: Option<String>,
    #[context]
    pci_slot: Option<String>,
    #[context]
    selection_source: Option<String>,
    #[context]
    reason: &'static str,
}

impl DynamicLog for ScoutPciEvaluated {
    /// Uses warning for results that need attention and debug for agreement.
    fn log_at(&self) -> LogAt {
        match self.result {
            EvaluationResult::Agreement => LogAt::Level(tracing::Level::DEBUG),
            EvaluationResult::Disagreement
            | EvaluationResult::Incomplete
            | EvaluationResult::Ambiguous => LogAt::Level(tracing::Level::WARN),
        }
    }
}

/// Compares PCI slots reported by Scout with the machine's stored boot interface.
pub(super) fn evaluate(hardware_info: &HardwareInfo, machine: &Machine) -> Option<Evaluation> {
    let eligible_interfaces = eligible_interfaces(machine);
    if eligible_interfaces.len() < 2 {
        return None;
    }

    let desired_mac_address = machine
        .config
        .desired_boot_interface
        .as_ref()
        .map(|target| target.value.mac_address());
    if desired_mac_address.is_some_and(|desired_mac_address| {
        !eligible_interfaces
            .iter()
            .any(|interface| interface.mac_address == desired_mac_address)
            && machine.status.interfaces.iter().any(|interface| {
                interface.machine_id == Some(machine.id)
                    && interface.mac_address == desired_mac_address
            })
    }) {
        return None;
    }

    if let Some(interface) = first_duplicate_mac(&eligible_interfaces) {
        return Some(Evaluation::from_machine(
            machine,
            EvaluationResult::Ambiguous,
            Some(EvaluationSubject::for_interface(interface)),
            "eligible interface MAC is not unique",
        ));
    }
    if let Some(interface) = first_duplicate_dpu(&eligible_interfaces) {
        return Some(Evaluation::from_machine(
            machine,
            EvaluationResult::Ambiguous,
            Some(EvaluationSubject::for_interface(interface)),
            "eligible interface DPU ID is not unique",
        ));
    }

    let candidates = match candidates_from_report(hardware_info, machine, &eligible_interfaces) {
        Ok(candidates) => candidates,
        Err(evaluation) => return Some(evaluation),
    };
    let candidate = candidates
        .into_iter()
        .min_by(|left, right| left.pci_slot.cmp(&right.pci_slot))?;

    let Some(desired_mac_address) = desired_mac_address else {
        return Some(Evaluation::from_machine(
            machine,
            EvaluationResult::Incomplete,
            Some(candidate.subject()),
            "stored boot interface is missing",
        ));
    };

    if !eligible_interfaces
        .iter()
        .any(|interface| interface.mac_address == desired_mac_address)
    {
        return Some(Evaluation::from_machine(
            machine,
            EvaluationResult::Incomplete,
            Some(candidate.subject()),
            "stored boot interface is not present on this host",
        ));
    }

    Some(compare_candidate(machine, candidate, desired_mac_address))
}

/// Collects this host's Admin interfaces that are attached to DPU machines.
fn eligible_interfaces(machine: &Machine) -> Vec<EligibleInterface> {
    let mut interfaces = machine
        .status
        .interfaces
        .iter()
        .filter_map(|interface| {
            let dpu_machine_id = interface.attached_dpu_machine_id?;
            (interface.machine_id == Some(machine.id)
                && interface.network_segment_type == Some(NetworkSegmentType::Admin)
                && dpu_machine_id.machine_type().is_dpu())
            .then_some(EligibleInterface {
                machine_interface_id: interface.id,
                mac_address: interface.mac_address,
                dpu_machine_id,
            })
        })
        .collect::<Vec<_>>();
    interfaces.sort_by_key(|interface| interface.machine_interface_id);
    interfaces
}

/// Returns the second interface carrying a repeated eligible MAC address.
fn first_duplicate_mac(interfaces: &[EligibleInterface]) -> Option<EligibleInterface> {
    let mut seen = HashSet::with_capacity(interfaces.len());
    interfaces
        .iter()
        .copied()
        .find(|interface| !seen.insert(interface.mac_address))
}

/// Returns the second interface carrying a repeated eligible DPU ID.
fn first_duplicate_dpu(interfaces: &[EligibleInterface]) -> Option<EligibleInterface> {
    let mut seen = HashSet::with_capacity(interfaces.len());
    interfaces
        .iter()
        .copied()
        .find(|interface| !seen.insert(interface.dpu_machine_id))
}

/// Matches every eligible MAC to one report row and one nonblank PCI slot.
fn candidates_from_report(
    hardware_info: &HardwareInfo,
    machine: &Machine,
    eligible_interfaces: &[EligibleInterface],
) -> Result<Vec<Candidate>, Evaluation> {
    let mut candidates = Vec::with_capacity(eligible_interfaces.len());

    for interface in eligible_interfaces {
        let mut matches = hardware_info
            .network_interfaces
            .iter()
            .filter(|reported| reported.mac_address == interface.mac_address);
        let Some(reported) = matches.next() else {
            return Err(Evaluation::from_machine(
                machine,
                EvaluationResult::Incomplete,
                Some(EvaluationSubject::for_interface(*interface)),
                "eligible interface has no Scout report row",
            ));
        };
        if matches.next().is_some() {
            return Err(Evaluation::from_machine(
                machine,
                EvaluationResult::Ambiguous,
                Some(EvaluationSubject::for_interface(*interface)),
                "eligible interface has multiple Scout report rows",
            ));
        }

        let Some(pci_slot) = reported
            .pci_properties
            .as_ref()
            .and_then(|properties| properties.slot.as_deref())
            .map(str::trim)
            .filter(|slot| !slot.is_empty())
        else {
            return Err(Evaluation::from_machine(
                machine,
                EvaluationResult::Incomplete,
                Some(EvaluationSubject::for_interface(*interface)),
                "eligible interface report has no PCI slot",
            ));
        };

        candidates.push(Candidate {
            interface: *interface,
            pci_slot: pci_slot.to_ascii_lowercase(),
        });
    }

    let mut slots = HashSet::with_capacity(candidates.len());
    if let Some(candidate) = candidates
        .iter()
        .find(|candidate| !slots.insert(candidate.pci_slot.as_str()))
    {
        return Err(Evaluation::from_machine(
            machine,
            EvaluationResult::Ambiguous,
            Some(candidate.subject()),
            "eligible interfaces share a reported PCI slot",
        ));
    }

    Ok(candidates)
}

/// Compares the Scout candidate with the stored desired boot interface MAC.
fn compare_candidate(
    machine: &Machine,
    candidate: Candidate,
    desired_mac_address: MacAddress,
) -> Evaluation {
    if candidate.interface.mac_address == desired_mac_address {
        Evaluation::from_machine(
            machine,
            EvaluationResult::Agreement,
            Some(candidate.subject()),
            "candidate matches the stored boot interface",
        )
    } else {
        Evaluation::from_machine(
            machine,
            EvaluationResult::Disagreement,
            Some(candidate.subject()),
            "candidate differs from the stored boot interface",
        )
    }
}

#[cfg(test)]
mod tests {
    use carbide_instrument::testing::{MetricsCapture, capture_logs};
    use carbide_test_support::{Check, check_values};
    use config_version::Versioned;
    use model::hardware_info::{NetworkInterface, PciDeviceProperties};
    use model::machine::MachineInterfaceSnapshot;
    use model::machine_boot_interface::MachineBootInterfaceTarget;
    use model::test_support::machine_snapshot::{
        config_version, dpu_machine_id, host_machine, host_machine_id,
    };

    use super::*;

    /// One variation from the complete, agreeing evaluator fixture.
    #[derive(Clone, Copy)]
    enum EvaluationCase {
        NotEnoughInterfaces,
        BdfOrdering,
        ReversedRows,
        Disagreement,
        SecondAgreement,
        DomainOrdering,
        NormalizedOrdering,
        StringOrdering,
        MissingRow,
        MissingPci,
        MissingSlot,
        BlankSlot,
        DuplicateRow,
        DuplicateSlot,
        DuplicateMac,
        DuplicateDpu,
        MissingDesired,
        UnknownDesired,
        IntegratedInterface,
        IntegratedDesired,
        IntegratedDesiredWithMissingSlot,
        ExtraReportRow,
    }

    /// Returns a deterministic MAC address for test interface identities.
    fn mac(index: u8) -> MacAddress {
        MacAddress::new([0x02, 0, 0, 0, 0, index])
    }

    /// Builds one Admin interface owned by the fixture host and attached to a DPU.
    fn eligible_interface(
        mac_address: MacAddress,
        dpu_machine_id: MachineId,
    ) -> MachineInterfaceSnapshot {
        let mut interface = MachineInterfaceSnapshot::mock_with_mac(mac_address);
        interface.id =
            MachineInterfaceId::from(uuid::Uuid::from_u128(u128::from(mac_address.bytes()[5])));
        interface.machine_id = Some(host_machine_id());
        interface.attached_dpu_machine_id = Some(dpu_machine_id);
        interface.network_segment_type = Some(NetworkSegmentType::Admin);
        interface
    }

    /// Builds an Admin interface owned by the host and not attached to a DPU.
    fn integrated_interface() -> MachineInterfaceSnapshot {
        let mut interface = MachineInterfaceSnapshot::mock_with_mac(mac(9));
        interface.id = MachineInterfaceId::from(uuid::Uuid::from_u128(9));
        interface.machine_id = Some(host_machine_id());
        interface.network_segment_type = Some(NetworkSegmentType::Admin);
        interface.attached_dpu_machine_id = None;
        interface
    }

    /// Builds one Scout network row with the supplied PCI slot.
    fn reported_interface(mac_address: MacAddress, slot: Option<&str>) -> NetworkInterface {
        NetworkInterface {
            mac_address,
            pci_properties: Some(PciDeviceProperties {
                vendor: String::new(),
                device: String::new(),
                path: String::new(),
                numa_node: 0,
                description: None,
                slot: slot.map(str::to_string),
            }),
        }
    }

    /// Builds a machine and returns the evaluator's bounded result.
    fn run_evaluation(case: EvaluationCase) -> Option<EvaluationResult> {
        let mut machine = host_machine();
        machine.status.interfaces = vec![
            eligible_interface(mac(1), dpu_machine_id(0)),
            eligible_interface(mac(2), dpu_machine_id(1)),
        ];
        let mut reports = vec![
            reported_interface(mac(1), Some("0000:02:00.0")),
            reported_interface(mac(2), Some("0000:0a:00.0")),
        ];
        let mut desired_mac_address = Some(mac(1));

        match case {
            EvaluationCase::NotEnoughInterfaces => machine.status.interfaces.truncate(1),
            EvaluationCase::BdfOrdering => {}
            EvaluationCase::ReversedRows => {
                machine.status.interfaces.reverse();
                reports.reverse();
            }
            EvaluationCase::Disagreement => {
                reports = vec![
                    reported_interface(mac(1), Some("0000:0a:00.0")),
                    reported_interface(mac(2), Some("0000:02:00.0")),
                ];
            }
            EvaluationCase::SecondAgreement => {
                reports = vec![
                    reported_interface(mac(1), Some("0000:0a:00.0")),
                    reported_interface(mac(2), Some("0000:02:00.0")),
                ];
                desired_mac_address = Some(mac(2));
            }
            EvaluationCase::DomainOrdering => {
                reports = vec![
                    reported_interface(mac(1), Some("0001:00:00.0")),
                    reported_interface(mac(2), Some("0000:ff:00.0")),
                ];
                desired_mac_address = Some(mac(2));
            }
            EvaluationCase::NormalizedOrdering => {
                reports = vec![
                    reported_interface(mac(1), Some(" 0000:0A:00.0 ")),
                    reported_interface(mac(2), Some("0000:0b:00.0")),
                ];
            }
            EvaluationCase::StringOrdering => {
                reports = vec![
                    reported_interface(mac(1), Some("Riser_Slot1")),
                    reported_interface(mac(2), Some("riser_slot2")),
                ];
            }
            EvaluationCase::MissingRow => {
                reports.remove(0);
            }
            EvaluationCase::MissingPci => reports[0].pci_properties = None,
            EvaluationCase::MissingSlot => {
                reports[0].pci_properties.as_mut().unwrap().slot = None;
            }
            EvaluationCase::BlankSlot => {
                reports[0].pci_properties.as_mut().unwrap().slot = Some(" \t".to_string());
            }
            EvaluationCase::DuplicateRow => reports.insert(0, reports[0].clone()),
            EvaluationCase::DuplicateSlot => {
                reports[1].pci_properties.as_mut().unwrap().slot =
                    Some(" 0000:02:00.0 ".to_string());
            }
            EvaluationCase::DuplicateMac => {
                machine.status.interfaces[1] = eligible_interface(mac(1), dpu_machine_id(1));
            }
            EvaluationCase::DuplicateDpu => {
                machine.status.interfaces[1] = eligible_interface(mac(2), dpu_machine_id(0));
            }
            EvaluationCase::MissingDesired => desired_mac_address = None,
            EvaluationCase::UnknownDesired => desired_mac_address = Some(mac(9)),
            EvaluationCase::IntegratedInterface => {
                machine.status.interfaces.push(integrated_interface());
                reports.push(reported_interface(mac(9), Some("0000:01:00.0")));
            }
            EvaluationCase::IntegratedDesired => {
                machine.status.interfaces.push(integrated_interface());
                reports.push(reported_interface(mac(9), Some("0000:01:00.0")));
                desired_mac_address = Some(mac(9));
            }
            EvaluationCase::IntegratedDesiredWithMissingSlot => {
                machine.status.interfaces.push(integrated_interface());
                reports[0].pci_properties.as_mut().unwrap().slot = None;
                desired_mac_address = Some(mac(9));
            }
            EvaluationCase::ExtraReportRow => {
                reports.push(reported_interface(mac(9), None));
            }
        }

        machine.config.desired_boot_interface = desired_mac_address.map(|address| {
            Versioned::new(
                MachineBootInterfaceTarget::MacOnly(address),
                config_version(20),
            )
        });

        let hardware_info = HardwareInfo {
            network_interfaces: reports,
            ..HardwareInfo::default()
        };
        evaluate(&hardware_info, &machine).map(|evaluation| evaluation.result)
    }

    /// Builds one compact evaluator table row.
    macro_rules! evaluation_case {
        ($scenario:literal, $input:ident, $expect:ident) => {
            Check {
                scenario: $scenario,
                input: EvaluationCase::$input,
                expect: Some(EvaluationResult::$expect),
            }
        };
        ($scenario:literal, $input:ident) => {
            Check {
                scenario: $scenario,
                input: EvaluationCase::$input,
                expect: None,
            }
        };
    }

    /// The evaluator covers ordering, completeness, ambiguity, and comparison as one table.
    #[test]
    fn evaluator_uses_complete_unambiguous_scout_slot_mappings() {
        check_values(
            [
                evaluation_case!(
                    "fewer than two eligible interfaces are ignored",
                    NotEnoughInterfaces
                ),
                evaluation_case!("slot 02 sorts before slot 0a", BdfOrdering, Agreement),
                evaluation_case!(
                    "stored and report row order do not affect selection",
                    ReversedRows,
                    Agreement
                ),
                evaluation_case!(
                    "lower second slot disagrees with the stored first interface",
                    Disagreement,
                    Disagreement
                ),
                evaluation_case!(
                    "lower second slot agrees with the stored second interface",
                    SecondAgreement,
                    Agreement
                ),
                evaluation_case!("lower domain sorts first", DomainOrdering, Agreement),
                evaluation_case!(
                    "slot comparison ignores case and surrounding whitespace",
                    NormalizedOrdering,
                    Agreement
                ),
                evaluation_case!(
                    "arbitrary slot values are compared as strings",
                    StringOrdering,
                    Agreement
                ),
                evaluation_case!("missing report row is incomplete", MissingRow, Incomplete),
                evaluation_case!(
                    "missing PCI properties are incomplete",
                    MissingPci,
                    Incomplete
                ),
                evaluation_case!("missing PCI slot is incomplete", MissingSlot, Incomplete),
                evaluation_case!("blank PCI slot is incomplete", BlankSlot, Incomplete),
                evaluation_case!("duplicate report row is ambiguous", DuplicateRow, Ambiguous),
                evaluation_case!(
                    "duplicate normalized PCI slot is ambiguous",
                    DuplicateSlot,
                    Ambiguous
                ),
                evaluation_case!(
                    "duplicate eligible MAC is ambiguous",
                    DuplicateMac,
                    Ambiguous
                ),
                evaluation_case!(
                    "duplicate eligible DPU identity is ambiguous",
                    DuplicateDpu,
                    Ambiguous
                ),
                evaluation_case!(
                    "missing stored target is incomplete",
                    MissingDesired,
                    Incomplete
                ),
                evaluation_case!(
                    "unknown stored target is incomplete",
                    UnknownDesired,
                    Incomplete
                ),
                evaluation_case!(
                    "integrated interface is excluded from DPU ordering",
                    IntegratedInterface,
                    Agreement
                ),
                evaluation_case!(
                    "integrated boot interface needs no DPU comparison",
                    IntegratedDesired
                ),
                evaluation_case!(
                    "integrated boot interface is ignored before DPU evidence is checked",
                    IntegratedDesiredWithMissingSlot
                ),
                evaluation_case!("unrelated Scout row is ignored", ExtraReportRow, Agreement),
            ],
            run_evaluation,
        );
    }

    /// One table covers every result's metric label and diagnostic level.
    #[test]
    fn event_emits_every_result_with_candidate_context() {
        /// Expected observable values for one bounded evaluation result.
        struct EventCase {
            result: EvaluationResult,
            label: &'static str,
            level: tracing::Level,
        }

        let cases = [
            EventCase {
                result: EvaluationResult::Agreement,
                label: "agreement",
                level: tracing::Level::DEBUG,
            },
            EventCase {
                result: EvaluationResult::Disagreement,
                label: "disagreement",
                level: tracing::Level::WARN,
            },
            EventCase {
                result: EvaluationResult::Incomplete,
                label: "incomplete",
                level: tracing::Level::WARN,
            },
            EventCase {
                result: EvaluationResult::Ambiguous,
                label: "ambiguous",
                level: tracing::Level::WARN,
            },
        ];
        let metrics = MetricsCapture::start();
        let machine_id = host_machine_id();
        let logs = capture_logs(|| {
            for case in &cases {
                Evaluation {
                    result: case.result,
                    subject: Some(EvaluationSubject {
                        mac_address: mac(1),
                        pci_slot: Some("0000:02:00.0".to_string()),
                    }),
                    desired_mac_address: Some(mac(1)),
                    selection_source: Some(BootInterfaceSelectionSource::RedfishUefiPci),
                    reason: "test reason",
                }
                .emit(&machine_id);
            }
        });

        assert_eq!(logs.len(), cases.len());
        for (index, case) in cases.iter().enumerate() {
            assert!(
                metrics.counter_delta(
                    "carbide_scout_pci_evaluations_total",
                    &[("result", case.label)],
                ) >= 1.0,
                "missing result series {}",
                case.label,
            );
            assert_eq!(
                logs[index].level, case.level,
                "wrong log level for {}",
                case.label,
            );
        }

        let machine_id = machine_id.to_string();
        assert_eq!(logs[0].field("machine_id"), Some(machine_id.as_str()));
        assert_eq!(
            logs[0].field("interface_mac_address"),
            Some("02:00:00:00:00:01")
        );
        assert_eq!(logs[0].field("pci_slot"), Some("0000:02:00.0"));
    }
}
