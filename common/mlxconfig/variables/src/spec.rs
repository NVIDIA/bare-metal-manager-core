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

// src/spec.rs
// This file defines the specs for different mlxconfig
// variable types (e.g. bools, ints, enums, etc), with
// a builder that is leveraged by a build.rs script to
// make building a little cleaner.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
