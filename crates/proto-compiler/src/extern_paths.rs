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

pub struct ExternPaths(Vec<(String, syn::Type)>);

pub type ExternPathSearchIndex<'a> = HashMap<&'a str, &'a syn::Type>;

impl ExternPaths {
    pub fn new<T: AsRef<str>>(input: impl Iterator<Item = (T, syn::Type)>) -> Self {
        Self(input.map(|(k, v)| (k.as_ref().to_string(), v)).collect())
    }

    pub fn build_index(&self) -> ExternPathSearchIndex<'_> {
        self.0.iter().map(|(k, v)| (k.as_str(), v)).collect()
    }
}

pub trait TonicBuilderExternPathsExt {
    fn extern_paths(self, paths: &ExternPaths) -> Self;
}

impl TonicBuilderExternPathsExt for tonic_prost_build::Builder {
    fn extern_paths(self, paths: &ExternPaths) -> Self {
        paths.0.iter().fold(self, |builder, (name, rust_type)| {
            builder.extern_path(name, quote::quote! { #rust_type }.to_string())
        })
    }
}
