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

use prost_reflect::{
    DescriptorPool, DynamicMessage, EnumDescriptor, ExtensionDescriptor, FileDescriptor, Kind,
    MessageDescriptor, ReflectMessage,
};

use crate::{Error, Schema};

pub(crate) struct Derive {
    // Fully qualified Prost matcher. Message matchers intentionally apply to
    // the message and all declarations nested within it.
    protobuf_type: String,
    derives: Vec<syn::Path>,
}

struct ExternPath {
    protobuf_type: String,
    rust_type: syn::Type,
}

/// Lookup index for protobuf-to-Rust external type mappings.
pub type ExternPathSearchIndex<'a> = HashMap<&'a str, &'a syn::Type>;

/// Validated code-generation configuration collected from protobuf options.
pub struct Codegen {
    type_derives: Vec<Derive>,
    extern_paths: Vec<ExternPath>,
}

impl Schema {
    /// Collects and validates all supported code-generation annotations.
    ///
    /// # Errors
    ///
    /// Returns an error when a required annotation extension is absent or has
    /// an unexpected shape, or when an annotation value is invalid.
    pub fn collect_codegen(&self) -> Result<Codegen, Error> {
        let message_derive_ext = self
            .descriptor_pool
            .derive_codegen_ext("carbide.codegen.v1.message_derive")?;
        let enum_derive_ext = self
            .descriptor_pool
            .derive_codegen_ext("carbide.codegen.v1.enum_derive")?;
        let message_extern_path_ext = self
            .descriptor_pool
            .extern_path_codegen_ext("carbide.codegen.v1.message_extern_path")?;
        let enum_extern_path_ext = self
            .descriptor_pool
            .extern_path_codegen_ext("carbide.codegen.v1.enum_extern_path")?;
        let imported_extern_path_ext = self
            .descriptor_pool
            .extern_path_codegen_ext("carbide.codegen.v1.imported_extern_path")?;

        // Type derives:
        let message_derives = self
            .descriptor_pool
            .all_messages()
            .map(|descriptor| descriptor.collect_derives(&message_derive_ext));
        let enum_derives = self
            .descriptor_pool
            .all_enums()
            .map(|descriptor| descriptor.collect_derives(&enum_derive_ext));

        let type_derives = message_derives
            .chain(enum_derives)
            .filter_map(|result| result.transpose())
            .collect::<Result<_, _>>()?;

        // Extern paths:
        let message_extern_paths = self
            .descriptor_pool
            .all_messages()
            .filter_map(|descriptor| descriptor.collect_extern_path(&message_extern_path_ext));
        let enum_extern_paths = self
            .descriptor_pool
            .all_enums()
            .filter_map(|descriptor| descriptor.collect_extern_path(&enum_extern_path_ext));
        let imported_extern_paths = self.descriptor_pool.files().flat_map(|descriptor| {
            descriptor
                .collect_imported_extern_paths(&imported_extern_path_ext, &self.descriptor_pool)
        });

        let extern_paths = message_extern_paths
            .chain(enum_extern_paths)
            .chain(imported_extern_paths)
            .collect::<Result<Vec<_>, _>>()?;

        // Ensure every protobuf type is mapped only once.
        extern_paths
            .iter()
            .try_fold(HashSet::new(), |mut declared, mapping| {
                if declared.insert(mapping.protobuf_type.as_str()) {
                    Ok(declared)
                } else {
                    Err(Error::RedeclaredExternPath {
                        protobuf_type: mapping.protobuf_type.clone(),
                    })
                }
            })
            .map(drop)?;

        Ok(Codegen {
            type_derives,
            extern_paths,
        })
    }
}

impl Codegen {
    /// Builds a borrowed index of the resolved external type mappings.
    pub fn extern_paths(&self) -> ExternPathSearchIndex<'_> {
        self.extern_paths
            .iter()
            .map(|mapping| (mapping.protobuf_type.as_str(), &mapping.rust_type))
            .collect()
    }
}

/// Applies collected protobuf code-generation annotations to a tonic builder.
pub trait TonicBuilderCodegenExt {
    /// Applies derives and external type mappings to this builder.
    fn apply_codegen(self, codegen: &Codegen) -> Self;
}

impl TonicBuilderCodegenExt for tonic_prost_build::Builder {
    fn apply_codegen(self, codegen: &Codegen) -> Self {
        let builder = codegen.extern_paths.iter().fold(self, |builder, mapping| {
            let rust_type = &mapping.rust_type;
            builder.extern_path(
                &mapping.protobuf_type,
                quote::quote! { #rust_type }.to_string(),
            )
        });
        codegen
            .type_derives
            .iter()
            .fold(builder, |builder, target| {
                target.derives.iter().fold(builder, |builder, attr| {
                    let attribute = quote::quote! {#[derive(#attr)]}.to_string();
                    builder.type_attribute(&target.protobuf_type, attribute)
                })
            })
    }
}

trait DescriptorPoolExt {
    fn derive_codegen_ext(&self, name: &'static str) -> Result<ExtensionDescriptor, Error>;
    fn extern_path_codegen_ext(&self, name: &'static str) -> Result<ExtensionDescriptor, Error>;
}

impl DescriptorPoolExt for DescriptorPool {
    fn derive_codegen_ext(&self, name: &'static str) -> Result<ExtensionDescriptor, Error> {
        self.get_extension_by_name(name)
            .ok_or(Error::MissingCodegenExtension(name))
            .and_then(|extension| {
                if extension.is_list() && extension.kind() == Kind::String {
                    Ok(extension)
                } else {
                    Err(Error::InvalidCodegenExtension(
                        extension.full_name().to_owned(),
                    ))
                }
            })
    }

    fn extern_path_codegen_ext(&self, name: &'static str) -> Result<ExtensionDescriptor, Error> {
        self.get_extension_by_name(name)
            .ok_or(Error::MissingCodegenExtension(name))
    }
}

impl ExternPath {
    fn from_mapping(mapping: &DynamicMessage, pool: &DescriptorPool) -> Result<Self, Error> {
        let protobuf_type = mapping.required_string("protobuf_type")?;
        let rust_type = mapping.required_string("rust_type")?;

        let protobuf_name = protobuf_type.trim_start_matches('.');
        match pool
            .get_message_by_name(protobuf_name)
            .map(drop)
            .or_else(|| pool.get_enum_by_name(protobuf_name).map(drop))
        {
            Some(()) => Self::parse(protobuf_type, rust_type),
            None => Err(Error::UnknownExternPathTarget { protobuf_type }),
        }
    }

    fn parse(protobuf_type: String, rust_type: String) -> Result<Self, Error> {
        let protobuf_type = if protobuf_type.starts_with('.') {
            protobuf_type
        } else {
            format!(".{protobuf_type}")
        };
        match syn::parse_str::<syn::TypePath>(&rust_type) {
            Ok(rust_type) => Ok(Self {
                protobuf_type,
                rust_type: syn::Type::Path(rust_type),
            }),
            Err(source) => Err(Error::InvalidRustExternPath {
                protobuf_type,
                rust_type,
                source,
            }),
        }
    }
}

trait DynamicMessageExt {
    fn required_string(&self, name: &str) -> Result<String, Error>;
}

impl DynamicMessageExt for DynamicMessage {
    fn required_string(&self, name: &str) -> Result<String, Error> {
        self.get_field_by_name(name)
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| Error::InvalidCodegenExtension(self.descriptor().full_name().to_owned()))
    }
}

trait CodegenTypeDescriptor {
    fn options(&self) -> DynamicMessage;
    fn full_name(&self) -> &str;
}

trait CollectDerives: CodegenTypeDescriptor {
    fn collect_derives(&self, ext: &ExtensionDescriptor) -> Result<Option<Derive>, Error> {
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

impl<T: CodegenTypeDescriptor> CollectDerives for T {}

trait CollectExternPath: CodegenTypeDescriptor {
    fn collect_extern_path(
        &self,
        extension: &ExtensionDescriptor,
    ) -> Option<Result<ExternPath, Error>> {
        self.options()
            .get_extension(extension)
            .as_str()
            .filter(|rust_type| !rust_type.is_empty())
            .map(str::to_owned)
            .map(|rust_type| ExternPath::parse(format!(".{}", self.full_name()), rust_type))
    }
}

impl<T: CodegenTypeDescriptor> CollectExternPath for T {}

trait CollectImportedExternPaths {
    fn collect_imported_extern_paths(
        &self,
        extension: &ExtensionDescriptor,
        pool: &DescriptorPool,
    ) -> Vec<Result<ExternPath, Error>>;
}

impl CollectImportedExternPaths for FileDescriptor {
    fn collect_imported_extern_paths(
        &self,
        extension: &ExtensionDescriptor,
        pool: &DescriptorPool,
    ) -> Vec<Result<ExternPath, Error>> {
        self.options()
            .get_extension(extension)
            .as_list()
            .into_iter()
            .flatten()
            .map(|mapping| {
                mapping
                    .as_message()
                    .ok_or_else(|| Error::InvalidCodegenExtension(extension.full_name().to_owned()))
                    .and_then(|mapping| ExternPath::from_mapping(mapping, pool))
            })
            .collect()
    }
}

impl CodegenTypeDescriptor for MessageDescriptor {
    fn full_name(&self) -> &str {
        MessageDescriptor::full_name(self)
    }
    fn options(&self) -> DynamicMessage {
        MessageDescriptor::options(self)
    }
}

impl CodegenTypeDescriptor for EnumDescriptor {
    fn full_name(&self) -> &str {
        EnumDescriptor::full_name(self)
    }
    fn options(&self) -> DynamicMessage {
        EnumDescriptor::options(self)
    }
}
