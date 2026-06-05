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

use carbide_uuid::dpu_remediations::RemediationId;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::{MachineId, MachineIdParseError};
use carbide_uuid::switch::{SwitchId, SwitchIdParseError};
use rpc::forge::MachineType;
use rpc::forge_tls_client::ForgeTlsClientError;

#[derive(thiserror::Error, Debug)]
pub enum CarbideCliError {
    #[error("Unable to connect to carbide API: {0}")]
    ApiConnectFailed(#[from] ForgeTlsClientError),

    #[error("The API call to the Forge API server returned {0}")]
    ApiInvocationError(#[from] tonic::Status),

    #[error("Error while writing into string: {0}")]
    StringWriteError(#[from] std::fmt::Error),

    #[error("Generic Error: {0}")]
    GenericError(String),

    #[error("Cannot specify both {0} and {1}. Please provide only one.")]
    ChooseOneError(&'static str, &'static str),

    #[error("Must specify either {0} or {1}.")]
    RequireOneError(&'static str, &'static str),

    #[error("Invalid datetime format: {0}. Use 'YYYY-MM-DD HH:MM:SS' or 'HH:MM:SS'")]
    InvalidDateTimeFromUserInput(String),

    #[error("Segment not found.")]
    SegmentNotFound,

    #[error("Domain not found.")]
    DomainNotFound,

    #[error("Uuid not found.")]
    UuidNotFound,

    #[error("MAC not found.")]
    MacAddressNotFound,

    #[error("Serial number not found.")]
    SerialNumberNotFound,

    #[error("Error while handling json: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Error while handling yaml: {0}")]
    YamlError(#[from] serde_yaml::Error),

    #[error("Error while handling csv: {0}")]
    CsvError(#[from] csv::Error),

    #[error("Unexpected machine type. Expected {0:?} but found {1:?}")]
    UnexpectedMachineType(MachineType, MachineType),

    #[error("Machine with id {0} not found")]
    MachineNotFound(MachineId),

    #[error("Switch with id {0} not found")]
    SwitchNotFound(SwitchId),

    #[error("Remediation with id {0} not found")]
    RemediationNotFound(RemediationId),

    #[error("Instance with id {0} not found")]
    InstanceNotFound(InstanceId),

    #[error("Tenant with id {0} not found")]
    TenantNotFound(String),

    #[error("I/O error. Does the file exist? {0}")]
    IOError(#[from] std::io::Error),

    /// For when you expected some values but the response was empty.
    /// If empty is acceptable don't use this.
    #[error("No results returned")]
    Empty,

    #[error("Not Implemented {0}")]
    NotImplemented(String),

    #[error("Invalid Machine id: {0}")]
    InvalidMachineId(#[from] MachineIdParseError),

    #[error("Invalid Switch id: {0}")]
    InvalidSwitchId(#[from] SwitchIdParseError),

    #[error("RPC data conversion error: {0}")]
    RpcDataConversionError(#[from] ::rpc::errors::RpcDataConversionError),

    #[error("Invalid Routing Profile Type: {0}")]
    InvalidRoutingProfileType(String),

    #[error(transparent)]
    EyreReport(eyre::Report),
}

impl From<eyre::Report> for CarbideCliError {
    // For commands that are [still] returning an eyre::Report,
    // and not a CarbideCliError, preserve the full report and
    // error chain for complete context.
    fn from(err: eyre::Report) -> Self {
        CarbideCliError::EyreReport(err)
    }
}

pub type CarbideCliResult<T> = Result<T, CarbideCliError>;
