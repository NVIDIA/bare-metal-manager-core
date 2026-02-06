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
use std::collections::HashMap;

use lazy_static::lazy_static;
use prost_types::FieldDescriptorProto;
use prost_types::field_descriptor_proto::{Label, Type};

lazy_static! {
    /// Hardcoded list of types that correspond to rust primitives. Taken from [prost-build][0]
    ///
    /// [0]: https://github.com/tokio-rs/prost/blob/9f5a38101afaeda951e563b4721f812cd0918214/prost-build/src/extern_paths.rs#L26
    pub(crate) static ref base_types: HashMap<String, String> = HashMap::from([
        (".google.protobuf.BoolValue".to_string(), "bool".to_string()),
        (
            ".google.protobuf.BytesValue".to_string(),
            "::prost::alloc::vec::Vec<u8>".to_string(),
        ),
        (
            ".google.protobuf.DoubleValue".to_string(),
            "f64".to_string(),
        ),
        (".google.protobuf.Empty".to_string(), "()".to_string()),
        (".google.protobuf.FloatValue".to_string(), "f32".to_string()),
        (".google.protobuf.Int32Value".to_string(), "i32".to_string()),
        (".google.protobuf.Int64Value".to_string(), "i64".to_string()),
        (
            ".google.protobuf.StringValue".to_string(),
            "::prost::alloc::string::String".to_string(),
        ),
        (
            ".google.protobuf.UInt32Value".to_string(),
            "u32".to_string(),
        ),
        (
            ".google.protobuf.UInt64Value".to_string(),
            "u64".to_string(),
        ),
    ]);
}

pub(crate) fn resolve_field_primitive_type(field: &FieldDescriptorProto) -> Option<String> {
    let str = match field.r#type() {
        Type::Float => String::from("f32"),
        Type::Double => String::from("f64"),
        Type::Uint32 | Type::Fixed32 => String::from("u32"),
        Type::Uint64 | Type::Fixed64 => String::from("u64"),
        Type::Int32 | Type::Sfixed32 | Type::Sint32 | Type::Enum => String::from("i32"),
        Type::Int64 | Type::Sfixed64 | Type::Sint64 => String::from("i64"),
        Type::Bool => String::from("bool"),
        Type::String => String::from("::prost::alloc::string::String"),
        Type::Bytes => String::from("Vec<u8>"),
        _ => return None,
    };
    Some(str)
}

pub(crate) fn field_is_optional(field: &FieldDescriptorProto) -> bool {
    if field.proto3_optional.unwrap_or(false) {
        return true;
    }

    if field.label() != Label::Optional {
        return false;
    }

    matches!(field.r#type(), Type::Message)
}
