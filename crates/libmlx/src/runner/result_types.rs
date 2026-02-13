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

// src/result_types.rs
// This module defines different types used for working with mlxconfig
// and its results (as part of mlxconfig-runner). This provides types
// for working with queries (QueriedVariable and QueryResult), sync
// operations (SyncResult), comparisons, and changes. Things like sync
// and compare will both give back a PlannedChange, and set and sync
// will both give back a VariableChange. The idea is, when possible,
// we generate a PlannedChange, then we execute (if doing a sync),
// and any time we execute something that changes (sync or set), we
// then return back a VariableChange for things that changed.

use std::time::Duration;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::protos::mlx_device::{
    ComparisonResult as ComparisonResultPb, PlannedChange as PlannedChangePb,
    QueriedDeviceInfo as QueriedDeviceInfoPb, QueriedVariable as QueriedVariablePb,
    QueryResult as QueryResultPb, SyncResult as SyncResultPb, VariableChange as VariableChangePb,
};
use serde::{Deserialize, Serialize};

use crate::variables::value::MlxConfigValue;
use crate::variables::variable::MlxConfigVariable;

// QueriedVariable is a complete representation of a queried
// variable from the device, populating all of the fields we
// get back, including proper translation of the variable
// values (next, current, and default) to their MlxConfigValue
// representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueriedVariable {
    // variable is the variable definition from registry.
    pub variable: MlxConfigVariable,
    // current_value is the current value on the device.
    pub current_value: MlxConfigValue,
    // default_value is the default device value.
    pub default_value: MlxConfigValue,
    // next_value is the next value to be applied to
    // the device, once the device is rebooted. This
    // will be different than the current_value if a
    // change has been made without a reboot yet.
    pub next_value: MlxConfigValue,
    // modified reports whether the next value is
    // different from the default value. This is
    // reported by the device.
    pub modified: bool,
    // read_only is whether variable is read only.
    // This is reported by the device.
    pub read_only: bool,
}

// QueriedVariable provides a few methods to make
// working with them easier, including a constructor
// of course, as well as some wrappers to get at
// underlying data (such as the variable name).
impl QueriedVariable {
    // new creates a new QueriedVariable with
    // all required parameters.
    pub fn new(
        variable: MlxConfigVariable,
        current_value: MlxConfigValue,
        default_value: MlxConfigValue,
        next_value: MlxConfigValue,
        modified: bool,
        read_only: bool,
    ) -> Self {
        Self {
            variable,
            current_value,
            default_value,
            next_value,
            modified,
            read_only,
        }
    }

    // name returns the variable name.
    pub fn name(&self) -> &str {
        &self.variable.name
    }

    // description returns the variable description.
    pub fn description(&self) -> &str {
        &self.variable.description
    }

    // is_pending_change returns whether there is a pending
    // change (which we know if next_value is different from
    // current_value).
    pub fn is_pending_change(&self) -> bool {
        // TODO(chet): PartialEq *should* work here for the entire
        // value, since defs should also match. If that ends up
        // being a problem, this can be .value for each of them.
        self.current_value != self.next_value
    }
}

// QueryResult contains the complete query response, with the
// info about the device we got the response from, and a list
// of every QueriedVariable result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    // device_info contains the device information
    // parsed from the JSON response.
    pub device_info: QueriedDeviceInfo,
    // variables contains all queried variables with their
    // complete state as per the device.
    pub variables: Vec<QueriedVariable>,
}

// QueriedDeviceInfo is a struct containing the info
// returned about the queried device.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QueriedDeviceInfo {
    // id is the "device" field from the JSON.
    pub device_id: Option<String>,
    pub device_type: Option<String>,
    // part_number is the "name" field from the returned
    // JSON. I don't know why they just didn't call it
    // part_number, but I'm fixing it here.
    pub part_number: Option<String>,
    pub description: Option<String>,
}

impl QueriedDeviceInfo {
    // new initializes a new empty DeviceInfo instance.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_device_id<T: Into<String>>(mut self, device_id: T) -> Self {
        self.device_id = Some(device_id.into());
        self
    }

    pub fn with_device_type<T: Into<String>>(mut self, device_type: T) -> Self {
        self.device_type = Some(device_type.into());
        self
    }

    pub fn with_part_number<T: Into<String>>(mut self, part_number: T) -> Self {
        self.part_number = Some(part_number.into());
        self
    }

    pub fn with_description<T: Into<String>>(mut self, description: T) -> Self {
        self.description = Some(description.into());
        self
    }
}

impl QueryResult {
    // new creates a new QueryResult.
    pub fn new(device_info: QueriedDeviceInfo, variables: Vec<QueriedVariable>) -> Self {
        Self {
            device_info,
            variables,
        }
    }

    // variable_count returns the number of variables
    // in the query result.
    pub fn variable_count(&self) -> usize {
        self.variables.len()
    }

    // get_variable returns a queried variable
    // from the query result.
    pub fn get_variable(&self, name: &str) -> Option<&QueriedVariable> {
        self.variables.iter().find(|v| v.name() == name)
    }

    // variable_names returns all variable names
    // from the query result variable list.
    pub fn variable_names(&self) -> Vec<&str> {
        self.variables.iter().map(|v| v.name()).collect()
    }
}

// SyncResult contains everything about the results
// of a sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    // variables_checked is the total number of
    // variables that were checked to sync.
    pub variables_checked: usize,
    // variables_changed is the total number of
    // variables that were actually changed.
    pub variables_changed: usize,
    // changes_applied are the actual changes
    // that ended up getting applied.
    pub changes_applied: Vec<VariableChange>,
    // execution_time is the execution time.
    #[serde(skip)]
    pub execution_time: Duration,
    // query_result contains the initial query
    // result before running the sync.
    pub query_result: QueryResult,
}

impl SyncResult {
    // new creates a new SyncResult with everything
    // needed to populate it.
    pub fn new(
        variables_checked: usize,
        variables_changed: usize,
        changes_applied: Vec<VariableChange>,
        execution_time: Duration,
        query_result: QueryResult,
    ) -> Self {
        Self {
            variables_checked,
            variables_changed,
            changes_applied,
            execution_time,
            query_result,
        }
    }

    // summary prints a summary of the sync result -- this
    // is mainly just for the CLI reference example for now.
    pub fn summary(&self) -> String {
        format!(
            "Sync complete: {}/{} variables changed in {:?}",
            self.variables_changed, self.variables_checked, self.execution_time
        )
    }
}

// ComparisonResult is the result of a comparison operation,
// showing what would change between the provided key=val
// settings and what is actually on the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonResult {
    // variables_checked is the total number of variables
    // that were checked.
    pub variables_checked: usize,
    // variables_needing_change is the total number of
    // variables that need to change.
    pub variables_needing_change: usize,
    // planned_changes is the list of planned changes.
    pub planned_changes: Vec<PlannedChange>,
    // query_result is the full query result from the
    // initial state check of the device.
    pub query_result: QueryResult,
}

impl ComparisonResult {
    // new creates a new ComparisonResult.
    pub fn new(
        variables_checked: usize,
        variables_needing_change: usize,
        planned_changes: Vec<PlannedChange>,
        query_result: QueryResult,
    ) -> Self {
        Self {
            variables_checked,
            variables_needing_change,
            planned_changes,
            query_result,
        }
    }

    // summary prints a summary of the comparison result -- this
    // is mainly just for the CLI reference example for now.
    pub fn summary(&self) -> String {
        format!(
            "Comparison complete: {}/{} variables would change",
            self.variables_needing_change, self.variables_checked
        )
    }
}

// PlannedChange represents a planned change for a variable
// before it is applied. It stores the variable, the current
// value we observed, and the desired value we are planning
// to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedChange {
    // variable_name is the name of the variable that
    // would change.
    pub variable_name: String,
    // current_value is the current value on the device.
    pub current_value: MlxConfigValue,
    // desired_value is the desired value to be set.
    pub desired_value: MlxConfigValue,
}

impl PlannedChange {
    // new creates a new PlannedChange.
    pub fn new(
        variable_name: String,
        current_value: MlxConfigValue,
        desired_value: MlxConfigValue,
    ) -> Self {
        Self {
            variable_name,
            current_value,
            desired_value,
        }
    }

    // description prints a description of the planned change -- this
    // is mainly just for the CLI reference example for now.
    pub fn description(&self) -> String {
        format!(
            "{}: {} → {}",
            self.variable_name, self.current_value, self.desired_value
        )
    }
}

// VariableChange represents a change that was successfully
// applied to a variable, containing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableChange {
    // variable_name is the variable that was changed.
    pub variable_name: String,
    // old_value is the value before the change was applied.
    pub old_value: MlxConfigValue,
    // new_value is the new value we applied (and should now
    // show as the next_value if we query again).
    pub new_value: MlxConfigValue,
}

impl VariableChange {
    // new creates a new VariableChange.
    pub fn new(
        variable_name: String,
        old_value: MlxConfigValue,
        new_value: MlxConfigValue,
    ) -> Self {
        Self {
            variable_name,
            old_value,
            new_value,
        }
    }

    // description prints a description of the change -- this
    // is mainly just for the CLI reference example for now.
    pub fn description(&self) -> String {
        format!(
            "{}: {} → {}",
            self.variable_name, self.old_value, self.new_value
        )
    }
}

// QueriedDeviceInfo conversions
impl From<QueriedDeviceInfo> for QueriedDeviceInfoPb {
    fn from(info: QueriedDeviceInfo) -> Self {
        QueriedDeviceInfoPb {
            device_id: info.device_id,
            device_type: info.device_type,
            part_number: info.part_number,
            description: info.description,
        }
    }
}

impl From<QueriedDeviceInfoPb> for QueriedDeviceInfo {
    fn from(pb: QueriedDeviceInfoPb) -> Self {
        QueriedDeviceInfo {
            device_id: pb.device_id,
            device_type: pb.device_type,
            part_number: pb.part_number,
            description: pb.description,
        }
    }
}

// QueriedVariable conversions
impl TryFrom<QueriedVariable> for QueriedVariablePb {
    type Error = RpcDataConversionError;

    fn try_from(var: QueriedVariable) -> Result<Self, Self::Error> {
        Ok(QueriedVariablePb {
            variable: Some(var.variable.into()),
            current_value: Some(var.current_value.into()),
            default_value: Some(var.default_value.into()),
            next_value: Some(var.next_value.into()),
            modified: var.modified,
            read_only: var.read_only,
        })
    }
}

impl TryFrom<QueriedVariablePb> for QueriedVariable {
    type Error = RpcDataConversionError;

    fn try_from(pb: QueriedVariablePb) -> Result<Self, Self::Error> {
        Ok(QueriedVariable {
            variable: pb
                .variable
                .ok_or(RpcDataConversionError::MissingArgument("variable"))?
                .try_into()?,
            current_value: pb
                .current_value
                .ok_or(RpcDataConversionError::MissingArgument("current_value"))?
                .try_into()?,
            default_value: pb
                .default_value
                .ok_or(RpcDataConversionError::MissingArgument("default_value"))?
                .try_into()?,
            next_value: pb
                .next_value
                .ok_or(RpcDataConversionError::MissingArgument("next_value"))?
                .try_into()?,
            modified: pb.modified,
            read_only: pb.read_only,
        })
    }
}

// QueryResult conversions
impl TryFrom<QueryResult> for QueryResultPb {
    type Error = RpcDataConversionError;

    fn try_from(result: QueryResult) -> Result<Self, Self::Error> {
        let variables: Result<Vec<_>, _> =
            result.variables.into_iter().map(|v| v.try_into()).collect();

        Ok(QueryResultPb {
            device_info: Some(result.device_info.into()),
            variables: variables?,
        })
    }
}

impl TryFrom<QueryResultPb> for QueryResult {
    type Error = RpcDataConversionError;

    fn try_from(pb: QueryResultPb) -> Result<Self, Self::Error> {
        let variables: Result<Vec<_>, _> = pb.variables.into_iter().map(|v| v.try_into()).collect();

        Ok(QueryResult {
            device_info: pb
                .device_info
                .ok_or(RpcDataConversionError::MissingArgument("device_info"))?
                .into(),
            variables: variables?,
        })
    }
}

// PlannedChange conversions
impl TryFrom<PlannedChange> for PlannedChangePb {
    type Error = RpcDataConversionError;

    fn try_from(change: PlannedChange) -> Result<Self, Self::Error> {
        Ok(PlannedChangePb {
            variable_name: change.variable_name,
            current_value: Some(change.current_value.into()),
            desired_value: Some(change.desired_value.into()),
        })
    }
}

impl TryFrom<PlannedChangePb> for PlannedChange {
    type Error = RpcDataConversionError;

    fn try_from(pb: PlannedChangePb) -> Result<Self, Self::Error> {
        Ok(PlannedChange {
            variable_name: pb.variable_name,
            current_value: pb
                .current_value
                .ok_or(RpcDataConversionError::MissingArgument("current_value"))?
                .try_into()?,
            desired_value: pb
                .desired_value
                .ok_or(RpcDataConversionError::MissingArgument("desired_value"))?
                .try_into()?,
        })
    }
}

// VariableChange conversions
impl TryFrom<VariableChange> for VariableChangePb {
    type Error = RpcDataConversionError;

    fn try_from(change: VariableChange) -> Result<Self, Self::Error> {
        Ok(VariableChangePb {
            variable_name: change.variable_name,
            old_value: Some(change.old_value.into()),
            new_value: Some(change.new_value.into()),
        })
    }
}

impl TryFrom<VariableChangePb> for VariableChange {
    type Error = RpcDataConversionError;

    fn try_from(pb: VariableChangePb) -> Result<Self, Self::Error> {
        Ok(VariableChange {
            variable_name: pb.variable_name,
            old_value: pb
                .old_value
                .ok_or(RpcDataConversionError::MissingArgument("old_value"))?
                .try_into()?,
            new_value: pb
                .new_value
                .ok_or(RpcDataConversionError::MissingArgument("new_value"))?
                .try_into()?,
        })
    }
}

// ComparisonResult conversions
impl TryFrom<ComparisonResult> for ComparisonResultPb {
    type Error = RpcDataConversionError;

    fn try_from(result: ComparisonResult) -> Result<Self, Self::Error> {
        let planned_changes: Result<Vec<_>, _> = result
            .planned_changes
            .into_iter()
            .map(|c| c.try_into())
            .collect();

        Ok(ComparisonResultPb {
            variables_checked: result.variables_checked as u64,
            variables_needing_change: result.variables_needing_change as u64,
            planned_changes: planned_changes?,
            query_result: Some(result.query_result.try_into()?),
        })
    }
}

impl TryFrom<ComparisonResultPb> for ComparisonResult {
    type Error = RpcDataConversionError;

    fn try_from(pb: ComparisonResultPb) -> Result<Self, Self::Error> {
        let planned_changes: Result<Vec<_>, _> = pb
            .planned_changes
            .into_iter()
            .map(|c| c.try_into())
            .collect();

        Ok(ComparisonResult {
            variables_checked: pb.variables_checked as usize,
            variables_needing_change: pb.variables_needing_change as usize,
            planned_changes: planned_changes?,
            query_result: pb
                .query_result
                .ok_or(RpcDataConversionError::MissingArgument("query_result"))?
                .try_into()?,
        })
    }
}

// SyncResult conversions
impl TryFrom<SyncResult> for SyncResultPb {
    type Error = RpcDataConversionError;

    fn try_from(result: SyncResult) -> Result<Self, Self::Error> {
        let changes_applied: Result<Vec<_>, _> = result
            .changes_applied
            .into_iter()
            .map(|c| c.try_into())
            .collect();

        Ok(SyncResultPb {
            variables_checked: result.variables_checked as u64,
            variables_changed: result.variables_changed as u64,
            changes_applied: changes_applied?,
            // Note: execution_time is not serialized (marked with serde(skip))
            query_result: Some(result.query_result.try_into()?),
        })
    }
}

impl TryFrom<SyncResultPb> for SyncResult {
    type Error = RpcDataConversionError;

    fn try_from(pb: SyncResultPb) -> Result<Self, Self::Error> {
        let changes_applied: Result<Vec<_>, _> = pb
            .changes_applied
            .into_iter()
            .map(|c| c.try_into())
            .collect();

        Ok(SyncResult {
            variables_checked: pb.variables_checked as usize,
            variables_changed: pb.variables_changed as usize,
            changes_applied: changes_applied?,
            // execution_time defaults to zero since it's not in protobuf
            execution_time: Duration::from_secs(0),
            query_result: pb
                .query_result
                .ok_or(RpcDataConversionError::MissingArgument("query_result"))?
                .try_into()?,
        })
    }
}
