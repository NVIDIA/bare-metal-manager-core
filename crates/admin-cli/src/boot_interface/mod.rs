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

//! The boot-interface command family: inspect the stores a machine's boot
//! interface lives in (`show`), list the candidate NICs with the picks the
//! system computes among them (`candidates`), and set the boot interface
//! (`set`). The views are projections of the `GetMachineBootInterfaces` RPC;
//! `set` fronts the same `SetPrimaryInterface` RPC as
//! `managed-host set-primary-interface`.

pub mod candidates;
pub mod set;
pub mod show;

use clap::Parser;

use crate::cfg::dispatch::Dispatch;

#[derive(Parser, Debug, Dispatch)]
pub enum Cmd {
    // Note for the abouts below: possessives are deliberately avoided -- the
    // man-page path (clap_mangen -> pandoc) drops apostrophes, so "a machine's
    // boot interface" renders as "a machines boot interface" in the generated
    // reference.
    #[clap(
        visible_alias = "details",
        about = "Show boot interfaces for a machine from every store (troubleshooting)",
        long_about = "Gather the boot-interface view for one machine from all four stores and \
            print them together: the managed `machine_interfaces` rows (authoritative for a \
            managed machine), `predicted_machine_interfaces` (pre-first-lease candidates), \
            the `explored_endpoints` default (for endpoints without a machine), and the \
            retained post-deletion pairs (including stale records). Also reports the \
            effective boot interface the system would select and flags when the stores \
            disagree. Read-only."
    )]
    Show(show::Args),
    #[clap(
        about = "List boot-interface candidates for a machine and the picks among them",
        long_about = "List every NIC that could be the boot interface for a machine -- the \
            managed `machine_interfaces` rows and the pre-first-lease predictions -- and \
            mark the picks among them: `current` (what resolution targets now: the primary \
            interface if one is set, else the lowest-MAC non-underlay interface), `default` \
            (what the automatic selection would choose if no primary interface were set), \
            and `explored` (the default site-explorer recorded for the BMC endpoint of the \
            machine). Underlay rows are listed but marked ineligible. Every pick is computed \
            server-side by the same selection code the machine-controller acts on. Read-only."
    )]
    Candidates(candidates::Args),
    #[clap(
        about = "Set the boot interface for a machine (promotes it to the primary interface)",
        long_about = "Make an interface the boot interface for a machine by promoting it to \
            the primary interface -- the designation every boot flow keys on. This is the \
            same operation as `managed-host set-primary-interface`: the BMC boot order is \
            updated first, then the primary flag moves in the database. The interface can be \
            named by machine-interface UUID or by MAC address; a MAC must match exactly one \
            managed interface row on the machine."
    )]
    Set(set::Args),
}
