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

// src/spec.rs
// This file defines the specs for different mlxconfig
// variable types (e.g. bools, ints, enums, etc), with
// a builder that is leveraged by a build.rs script to
// make building a little cleaner.

use std::fmt;

use ::rpc::errors::RpcDataConversionError;
use ::rpc::protos::mlx_device::{
    MlxVariableSpec as MlxVariableSpecPb, mlx_variable_spec as mlx_variable_spec_pb,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "config", rename_all = "snake_case")]
pub enum MlxVariableSpec {
    Boolean,
    Integer,
    String,
    Binary,
    Bytes,
    Array,
    Enum { options: Vec<String> },
    Preset { max_preset: u8 },
    BooleanArray { size: usize },
    IntegerArray { size: usize },
    EnumArray { options: Vec<String>, size: usize },
    BinaryArray { size: usize },
    Opaque,
}

// Much simpler builder - no redundant variant enum needed!
pub struct MlxVariableSpecBuilder;

impl MlxVariableSpec {
    pub fn builder() -> MlxVariableSpecBuilder {
        MlxVariableSpecBuilder
    }
}

impl MlxVariableSpecBuilder {
    // Simple variants also return builders for consistency
    pub fn boolean(self) -> SimpleBuilder {
        SimpleBuilder {
            spec: MlxVariableSpec::Boolean,
        }
    }

    pub fn integer(self) -> SimpleBuilder {
        SimpleBuilder {
            spec: MlxVariableSpec::Integer,
        }
    }

    pub fn string(self) -> SimpleBuilder {
        SimpleBuilder {
            spec: MlxVariableSpec::String,
        }
    }

    pub fn binary(self) -> SimpleBuilder {
        SimpleBuilder {
            spec: MlxVariableSpec::Binary,
        }
    }

    pub fn bytes(self) -> SimpleBuilder {
        SimpleBuilder {
            spec: MlxVariableSpec::Bytes,
        }
    }

    pub fn array(self) -> SimpleBuilder {
        SimpleBuilder {
            spec: MlxVariableSpec::Array,
        }
    }

    pub fn opaque(self) -> SimpleBuilder {
        SimpleBuilder {
            spec: MlxVariableSpec::Opaque,
        }
    }

    // For variants that need parameters, create them directly
    pub fn enum_type(self) -> EnumBuilder {
        EnumBuilder { options: None }
    }

    pub fn preset(self) -> PresetBuilder {
        PresetBuilder { max_preset: None }
    }

    pub fn boolean_array(self) -> BooleanArrayBuilder {
        BooleanArrayBuilder { size: None }
    }

    pub fn integer_array(self) -> IntegerArrayBuilder {
        IntegerArrayBuilder { size: None }
    }

    pub fn binary_array(self) -> BinaryArrayBuilder {
        BinaryArrayBuilder { size: None }
    }

    pub fn enum_array(self) -> EnumArrayBuilder {
        EnumArrayBuilder {
            options: None,
            size: None,
        }
    }
}

// Simple builder for variants that don't need configuration
pub struct SimpleBuilder {
    spec: MlxVariableSpec,
}

impl SimpleBuilder {
    pub fn build(self) -> MlxVariableSpec {
        self.spec
    }
}

// Focused builders for variants that need configuration
pub struct EnumBuilder {
    options: Option<Vec<String>>,
}

impl EnumBuilder {
    pub fn with_options<T: Into<Vec<String>>>(mut self, options: T) -> Self {
        self.options = Some(options.into());
        self
    }

    pub fn build(self) -> MlxVariableSpec {
        MlxVariableSpec::Enum {
            options: self.options.unwrap_or_default(),
        }
    }
}

pub struct PresetBuilder {
    max_preset: Option<u8>,
}

impl PresetBuilder {
    pub fn with_max_preset(mut self, max_preset: u8) -> Self {
        self.max_preset = Some(max_preset);
        self
    }

    pub fn build(self) -> MlxVariableSpec {
        MlxVariableSpec::Preset {
            max_preset: self.max_preset.unwrap_or(0),
        }
    }
}

pub struct BooleanArrayBuilder {
    size: Option<usize>,
}

impl BooleanArrayBuilder {
    pub fn with_size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    pub fn build(self) -> MlxVariableSpec {
        MlxVariableSpec::BooleanArray {
            size: self.size.unwrap_or(1),
        }
    }
}

pub struct IntegerArrayBuilder {
    size: Option<usize>,
}

impl IntegerArrayBuilder {
    pub fn with_size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    pub fn build(self) -> MlxVariableSpec {
        MlxVariableSpec::IntegerArray {
            size: self.size.unwrap_or(1),
        }
    }
}

pub struct BinaryArrayBuilder {
    size: Option<usize>,
}

impl BinaryArrayBuilder {
    pub fn with_size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    pub fn build(self) -> MlxVariableSpec {
        MlxVariableSpec::BinaryArray {
            size: self.size.unwrap_or(1),
        }
    }
}

pub struct EnumArrayBuilder {
    options: Option<Vec<String>>,
    size: Option<usize>,
}

impl EnumArrayBuilder {
    pub fn with_options<T: Into<Vec<String>>>(mut self, options: T) -> Self {
        self.options = Some(options.into());
        self
    }

    pub fn with_size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    pub fn build(self) -> MlxVariableSpec {
        MlxVariableSpec::EnumArray {
            options: self.options.unwrap_or_default(),
            size: self.size.unwrap_or(1),
        }
    }
}

impl fmt::Display for MlxVariableSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MlxVariableSpec::Boolean => write!(f, "Boolean"),
            MlxVariableSpec::Integer => write!(f, "Integer"),
            MlxVariableSpec::String => write!(f, "String"),
            MlxVariableSpec::Binary => write!(f, "Binary"),
            MlxVariableSpec::Bytes => write!(f, "Bytes"),
            MlxVariableSpec::Array => write!(f, "Array"),
            MlxVariableSpec::Enum { options } => {
                write!(f, "Enum [{}]", options.join(", "))
            }
            MlxVariableSpec::Preset { max_preset } => {
                write!(f, "Preset (max: {max_preset})")
            }
            MlxVariableSpec::BooleanArray { size } => {
                write!(f, "BooleanArray[{size}]")
            }
            MlxVariableSpec::IntegerArray { size } => {
                write!(f, "IntegerArray[{size}]")
            }
            MlxVariableSpec::EnumArray { options, size } => {
                write!(f, "EnumArray[{size}] [{}]", options.join(", "))
            }
            MlxVariableSpec::BinaryArray { size } => {
                write!(f, "BinaryArray[{size}]")
            }
            MlxVariableSpec::Opaque => write!(f, "Opaque"),
        }
    }
}

impl From<MlxVariableSpec> for MlxVariableSpecPb {
    fn from(spec: MlxVariableSpec) -> Self {
        match spec {
            MlxVariableSpec::Boolean => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::Boolean(
                    mlx_variable_spec_pb::BooleanSpec {},
                )),
            },
            MlxVariableSpec::Integer => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::Integer(
                    mlx_variable_spec_pb::IntegerSpec {},
                )),
            },
            MlxVariableSpec::String => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::String(
                    mlx_variable_spec_pb::StringSpec {},
                )),
            },
            MlxVariableSpec::Binary => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::Binary(
                    mlx_variable_spec_pb::BinarySpec {},
                )),
            },
            MlxVariableSpec::Bytes => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::Bytes(
                    mlx_variable_spec_pb::BytesSpec {},
                )),
            },
            MlxVariableSpec::Array => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::Array(
                    mlx_variable_spec_pb::ArraySpec {},
                )),
            },
            MlxVariableSpec::Enum { options } => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::EnumType(
                    mlx_variable_spec_pb::EnumSpec { options },
                )),
            },
            MlxVariableSpec::Preset { max_preset } => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::Preset(
                    mlx_variable_spec_pb::PresetSpec {
                        max_preset: max_preset as u32,
                    },
                )),
            },
            MlxVariableSpec::BooleanArray { size } => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::BooleanArray(
                    mlx_variable_spec_pb::BooleanArraySpec { size: size as u64 },
                )),
            },
            MlxVariableSpec::IntegerArray { size } => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::IntegerArray(
                    mlx_variable_spec_pb::IntegerArraySpec { size: size as u64 },
                )),
            },
            MlxVariableSpec::EnumArray { options, size } => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::EnumArray(
                    mlx_variable_spec_pb::EnumArraySpec {
                        options,
                        size: size as u64,
                    },
                )),
            },
            MlxVariableSpec::BinaryArray { size } => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::BinaryArray(
                    mlx_variable_spec_pb::BinaryArraySpec { size: size as u64 },
                )),
            },
            MlxVariableSpec::Opaque => MlxVariableSpecPb {
                spec_type: Some(mlx_variable_spec_pb::SpecType::Opaque(
                    mlx_variable_spec_pb::OpaqueSpec {},
                )),
            },
        }
    }
}

impl TryFrom<MlxVariableSpecPb> for MlxVariableSpec {
    type Error = RpcDataConversionError;

    fn try_from(pb: MlxVariableSpecPb) -> Result<Self, Self::Error> {
        let spec_type = pb
            .spec_type
            .ok_or(RpcDataConversionError::MissingArgument("spec_type"))?;

        match spec_type {
            mlx_variable_spec_pb::SpecType::Boolean(_) => Ok(MlxVariableSpec::Boolean),
            mlx_variable_spec_pb::SpecType::Integer(_) => Ok(MlxVariableSpec::Integer),
            mlx_variable_spec_pb::SpecType::String(_) => Ok(MlxVariableSpec::String),
            mlx_variable_spec_pb::SpecType::Binary(_) => Ok(MlxVariableSpec::Binary),
            mlx_variable_spec_pb::SpecType::Bytes(_) => Ok(MlxVariableSpec::Bytes),
            mlx_variable_spec_pb::SpecType::Array(_) => Ok(MlxVariableSpec::Array),
            mlx_variable_spec_pb::SpecType::EnumType(e) => {
                Ok(MlxVariableSpec::Enum { options: e.options })
            }
            mlx_variable_spec_pb::SpecType::Preset(p) => Ok(MlxVariableSpec::Preset {
                max_preset: p.max_preset as u8,
            }),
            mlx_variable_spec_pb::SpecType::BooleanArray(ba) => Ok(MlxVariableSpec::BooleanArray {
                size: ba.size as usize,
            }),
            mlx_variable_spec_pb::SpecType::IntegerArray(ia) => Ok(MlxVariableSpec::IntegerArray {
                size: ia.size as usize,
            }),
            mlx_variable_spec_pb::SpecType::EnumArray(ea) => Ok(MlxVariableSpec::EnumArray {
                options: ea.options,
                size: ea.size as usize,
            }),
            mlx_variable_spec_pb::SpecType::BinaryArray(ba) => Ok(MlxVariableSpec::BinaryArray {
                size: ba.size as usize,
            }),
            mlx_variable_spec_pb::SpecType::Opaque(_) => Ok(MlxVariableSpec::Opaque),
        }
    }
}
