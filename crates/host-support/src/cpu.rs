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
use std::collections::{HashMap, HashSet};

use ::rpc::machine_discovery as rpc_discovery;

pub fn aggregate_cpus(cpus: &[rpc_discovery::Cpu]) -> Vec<rpc_discovery::CpuInfo> {
    //
    //  Process CPU data
    //

    // This logic is ported from forge-cloud/cloud-backend. The handling of multiple CPU models on
    // a single machine is possibly misleading, but possibly it handles some future build, and it
    // accumulates all the info in any case. This function should return a vector with only one
    // CpuInfo.
    //
    // Number of unique sockets is cpu count.
    // Highest core number + 1 is the number of cores per socket.
    // Highest Number + 1 is total thread count, which
    // we'll divide by number of sockets later.

    let mut cpu_map = HashMap::<String, CpuAccumulator>::new();
    let mut cpu_socket_set = HashSet::<(String, u32)>::new();
    // Go through the CPUs listed in the hardware info and accumulate the details.
    for cpu in cpus.iter() {
        match cpu_map.get_mut(&cpu.model) {
            None => {
                // Insert into the socket map so we don't keep incrementing cpu count
                // as we look for threads and cores.
                cpu_socket_set.insert((cpu.model.clone(), cpu.socket));

                cpu_map.insert(
                    cpu.model.clone(),
                    CpuAccumulator {
                        model: cpu.model.clone(),
                        vendor: cpu.vendor.clone(),
                        sockets: 1,
                        cores: cpu.core + 1,
                        threads: cpu.number + 1,
                    },
                );
            }
            Some(accumulator) => {
                // If the socket hasn't been seen yet (i.e., if it's new to the set),
                // increment the cpu count.
                if cpu_socket_set.insert((cpu.model.clone(), cpu.socket)) {
                    accumulator.sockets += 1;
                }

                let core_count = cpu.core + 1;
                if core_count > accumulator.cores {
                    accumulator.cores = core_count;
                }

                let thread_count = cpu.number + 1;
                if thread_count > accumulator.threads {
                    accumulator.threads = thread_count;
                }
            }
        };
    }

    let mut values: Vec<&CpuAccumulator> = cpu_map.values().collect();
    values.sort_by_key(|v| &v.model);
    values
        .into_iter()
        .map(rpc_discovery::CpuInfo::from)
        .collect()
}

// Same as rpc_discovery::CpuInfo but with total thread count before computing threads per socket
pub(crate) struct CpuAccumulator {
    model: String,
    vendor: String,
    sockets: u32,
    cores: u32,
    threads: u32,
}

impl From<&CpuAccumulator> for rpc_discovery::CpuInfo {
    fn from(src: &CpuAccumulator) -> Self {
        let threads_per_socket = src.threads.checked_div(src.sockets).unwrap_or(0);

        rpc_discovery::CpuInfo {
            model: src.model.clone(),
            vendor: src.vendor.clone(),
            sockets: src.sockets,
            cores: src.cores,
            threads: threads_per_socket,
        }
    }
}
