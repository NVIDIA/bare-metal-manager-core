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

use crate::{Error, Schema};

pub(crate) struct Derive {
    // Fully qualified Prost matcher. Message matchers intentionally apply to
    // the message and all declarations nested within it.
    protobuf_type: String,
    derives: Vec<syn::Path>,
}

pub struct Codegen {
    type_derives: Vec<Derive>,
}

impl Schema {
    pub fn collect_codegen(&self) -> Result<Codegen, Error> {
        let message_ext = self
            .descriptor_pool
            .codegen_ext("carbide.codegen.v1.message_derive")?;
        let enum_ext = self
            .descriptor_pool
            .codegen_ext("carbide.codegen.v1.enum_derive")?;

        let message_derives = self
            .descriptor_pool
            .all_messages()
            .map(|descriptor| descriptor.collect_derives(&message_ext));
        let enum_derives = self
            .descriptor_pool
            .all_enums()
            .map(|descriptor| descriptor.collect_derives(&enum_ext));

        let type_derives = message_derives
            .chain(enum_derives)
            .filter_map(|result| result.transpose())
            .collect::<Result<_, _>>()?;

        Ok(Codegen { type_derives })
    }
}

pub trait TonicBuilderCodegenExt {
    fn apply_codegen(self, codegen: &Codegen) -> Self;
}

impl TonicBuilderCodegenExt for tonic_prost_build::Builder {
    fn apply_codegen(self, codegen: &Codegen) -> Self {
        codegen.type_derives.iter().fold(self, |builder, target| {
            target.derives.iter().fold(builder, |builder, attr| {
                let attribute = quote::quote! {#[derive(#attr)]}.to_string();
                builder.type_attribute(&target.protobuf_type, attribute)
            })
        })
    }
}

trait DescriptorPoolExt {
    fn codegen_ext(&self, name: &'static str) -> Result<prost_reflect::ExtensionDescriptor, Error>;
}

impl DescriptorPoolExt for prost_reflect::DescriptorPool {
    fn codegen_ext(&self, name: &'static str) -> Result<prost_reflect::ExtensionDescriptor, Error> {
        fn validate_derive(
            d: prost_reflect::ExtensionDescriptor,
        ) -> Result<prost_reflect::ExtensionDescriptor, Error> {
            if !d.is_list() || d.kind() != prost_reflect::Kind::String {
                Err(Error::InvalidCodegenExtension(d.full_name().to_owned()))
            } else {
                Ok(d)
            }
        }
        self.get_extension_by_name(name)
            .ok_or(Error::MissingCodegenExtension(name))
            .and_then(validate_derive)
    }
}

trait CollectDerives {
    fn options(&self) -> prost_reflect::DynamicMessage;
    fn full_name(&self) -> &str;
    fn collect_derives(
        &self,
        ext: &prost_reflect::ExtensionDescriptor,
    ) -> Result<Option<Derive>, Error> {
        let derives = self
            .options()
            .get_extension(ext)
            .as_list()
            .into_iter()
            .flatten()
            .flat_map(|value| {
                value.as_str().map(|str_value| {
                    syn::parse_str::<syn::Path>(str_value).map_err(|source| {
                        Error::InvalidRustDerive {
                            protobuf_type: self.full_name().to_owned(),
                            derive: str_value.to_owned(),
                            source,
                        }
                    })
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(if derives.is_empty() {
            None
        } else {
            Some(Derive {
                protobuf_type: format!(".{}", self.full_name()),
                derives,
            })
        })
    }
}

impl CollectDerives for prost_reflect::MessageDescriptor {
    fn full_name(&self) -> &str {
        prost_reflect::MessageDescriptor::full_name(self)
    }
    fn options(&self) -> prost_reflect::DynamicMessage {
        prost_reflect::MessageDescriptor::options(self)
    }
}

impl CollectDerives for prost_reflect::EnumDescriptor {
    fn full_name(&self) -> &str {
        prost_reflect::EnumDescriptor::full_name(self)
    }
    fn options(&self) -> prost_reflect::DynamicMessage {
        prost_reflect::EnumDescriptor::options(self)
    }
}
