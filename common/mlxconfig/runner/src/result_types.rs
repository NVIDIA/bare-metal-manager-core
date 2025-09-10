/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

// src/result_types.rs
// Result types defines different types used for working with mlxconfig
// and its results (as part of mlxconfig-runner). This provides types
// for working with queries (QueriedVariable and QueryResult), sync
// operations (SyncResult), comparisons, and changes. Things like sync
// and compare will both give back a PlannedChange, and set and sync
// will both give back a VariableChange. The idea is, when possible,
// we generate a PlannedChange, then we execute (if doing a sync),
// and any time we execute something that changes (sync or set), we
// then return back a VariableChange for things that changed.

use mlxconfig_variables::{DeviceInfo, MlxConfigValue, MlxConfigVariable};
use serde::{Deserialize, Serialize};
use std::time::Duration;

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
    pub device_info: DeviceInfo,
    // variables contains all queried variables with their
    // complete state as per the device.
    pub variables: Vec<QueriedVariable>,
}

impl QueryResult {
    // new creates a new QueryResult.
    pub fn new(device_info: DeviceInfo, variables: Vec<QueriedVariable>) -> Self {
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
