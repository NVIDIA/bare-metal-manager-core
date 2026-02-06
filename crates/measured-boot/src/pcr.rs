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

/*!
 *  Common code for working with the database. Provides constants and generics
 *  for making boilerplate copy-pasta code handled in a common way.
*/

use std::collections::HashSet;
use std::convert::{From, Into};
use std::fmt;
use std::hash::Hash;
use std::vec::Vec;

use rpc::protos::measured_boot::PcrRegisterValuePb;

// PcrRange is a small struct used when parsing
// --pcr-register values from the CLI as part of
// the parse_pcr_index_input function.
#[derive(Clone, Debug)]
pub struct PcrRange {
    pub start: usize,
    pub end: usize,
}

impl fmt::Display for PcrRange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.start, self.end)
    }
}

/// PcrSet is a list of PCR register indexes that are expected
/// to be targeted. For example: 0,1,2,5,6. With this PCR set,
/// an incoming list of PcrRegisterValues will have any values
/// whose indexes match the register numbers from the PcrSet.
///
/// This includes implementations for iterating.
#[derive(Clone, Debug)]
pub struct PcrSet(pub Vec<i16>);

impl Default for PcrSet {
    fn default() -> Self {
        Self::new()
    }
}

impl PcrSet {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn iter(&'_ self) -> PcrSetIter<'_> {
        PcrSetIter {
            current_slice: &self.0,
        }
    }
}

impl fmt::Display for PcrSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let vals: Vec<String> = self.iter().map(|&val| val.to_string()).collect();
        write!(f, "{}", vals.join(","))
    }
}

impl IntoIterator for PcrSet {
    type Item = i16;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'p> IntoIterator for &'p PcrSet {
    type Item = &'p i16;
    type IntoIter = std::slice::Iter<'p, i16>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[derive(Clone, Debug)]
pub struct PcrSetIter<'i> {
    current_slice: &'i [i16],
}

impl<'i> Iterator for PcrSetIter<'i> {
    type Item = &'i i16;

    fn next(&mut self) -> Option<Self::Item> {
        if !self.current_slice.is_empty() {
            let (first, rest) = self.current_slice.split_first().unwrap();
            self.current_slice = rest;
            Some(first)
        } else {
            None
        }
    }
}

pub fn parse_pcr_index_input(arg: &str) -> super::Result<PcrSet> {
    let groups: Vec<&str> = arg.split(',').collect();
    let mut index_set: HashSet<i16> = HashSet::new();
    for group in groups {
        if group.contains('-') {
            let pcr_range = parse_range(group)?;
            for index in pcr_range.start..=pcr_range.end {
                index_set.insert(index as i16);
            }
        } else {
            index_set.insert(group.parse::<i16>().map_err(|e| {
                super::Error::Parse(format!(
                    "parse_pcr_index_input group parse failed: {group}, {e}"
                ))
            })?);
        }
    }

    let mut vals: Vec<i16> = index_set.into_iter().collect();
    vals.sort();
    Ok(PcrSet(vals))
}

pub fn parse_range(arg: &str) -> super::Result<PcrRange> {
    let range: Vec<usize> = arg
        .split('-')
        .map(|s| {
            s.parse::<usize>()
                .map_err(|_| super::Error::Parse(format!("parse_range failed on {arg}")))
        })
        .collect::<super::Result<Vec<usize>>>()?;

    if range.len() != 2 {
        return Err(super::Error::Parse(String::from(
            "parse_range range expected 2 values",
        )));
    }

    if range[0] > range[1] {
        return Err(super::Error::Parse(String::from(
            "end must be greater than start",
        )));
    }

    Ok(PcrRange {
        start: range[0],
        end: range[1],
    })
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct PcrRegisterValue {
    pub pcr_register: i16,
    pub sha_any: String,
}

pub struct PcrRegisterValueVec(Vec<PcrRegisterValue>);

impl PcrRegisterValueVec {
    pub fn into_inner(self) -> Vec<PcrRegisterValue> {
        self.0
    }
}

impl PcrRegisterValue {
    pub fn from_pb_vec(pbs: Vec<PcrRegisterValuePb>) -> Vec<Self> {
        pbs.into_iter().map(|value| value.into()).collect()
    }

    pub fn to_pb_vec(values: &[Self]) -> Vec<PcrRegisterValuePb> {
        values.iter().map(|value| value.clone().into()).collect()
    }
}

impl From<PcrRegisterValue> for PcrRegisterValuePb {
    fn from(val: PcrRegisterValue) -> Self {
        Self {
            pcr_register: val.pcr_register as i32,
            sha_any: val.sha_any,
        }
    }
}

impl From<PcrRegisterValuePb> for PcrRegisterValue {
    fn from(msg: PcrRegisterValuePb) -> Self {
        Self {
            pcr_register: msg.pcr_register as i16,
            sha_any: msg.sha_any,
        }
    }
}

impl From<Vec<String>> for PcrRegisterValueVec {
    fn from(pcr_strings: Vec<String>) -> Self {
        let pcr_register_values = pcr_strings
            .into_iter()
            .enumerate()
            .map(|(pcr_index, pcr_val)| PcrRegisterValue {
                pcr_register: pcr_index as i16,
                sha_any: pcr_val,
            })
            .collect();
        PcrRegisterValueVec(pcr_register_values)
    }
}
