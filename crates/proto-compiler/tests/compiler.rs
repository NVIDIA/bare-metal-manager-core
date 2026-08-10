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

use std::path::Path;

use carbide_proto_compiler::{CompilerConfig, Error, Schema, compile};
use prost::Message as _;
use prost_reflect::{DescriptorPool, DynamicMessage, Kind};

const FIXTURE_PACKAGE: &str = "carbide.proto.compiler.fixture";
const OPTION_NAME: &str = "carbide.proto.compiler.fixture.method_annotation";

fn compile_fixture(name: &str) -> Result<Schema, Error> {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    compile(&CompilerConfig {
        proto_files: vec![fixtures.join(name)],
        include_paths: vec![fixtures],
        protoc_args: Vec::new(),
    })
}

fn annotation(pool: &DescriptorPool) -> DynamicMessage {
    let extension = pool
        .get_extension_by_name(OPTION_NAME)
        .expect("fixture option resolves by fully qualified name");
    assert_eq!(
        extension.containing_message().full_name(),
        "google.protobuf.MethodOptions"
    );

    let Kind::Message(payload) = extension.kind() else {
        panic!("fixture option has a message payload");
    };
    assert!(matches!(
        payload
            .get_field_by_name("enabled")
            .expect("enabled field exists")
            .kind(),
        Kind::Bool
    ));
    assert!(matches!(
        payload
            .get_field_by_name("limit")
            .expect("limit field exists")
            .kind(),
        Kind::Uint32
    ));
    assert!(matches!(
        payload
            .get_field_by_name("label")
            .expect("label field exists")
            .kind(),
        Kind::String
    ));

    let service = pool
        .get_service_by_name(&format!("{FIXTURE_PACKAGE}.FixtureService"))
        .expect("fixture service exists");
    let method = service
        .methods()
        .find(|method| method.name() == "Annotated")
        .expect("annotated fixture method exists");
    let options = method.options();
    assert!(options.has_extension(&extension));
    options
        .get_extension(&extension)
        .as_message()
        .expect("fixture option value is a message")
        .clone()
}

#[test]
fn compilation_preserves_structural_descriptor_data() {
    let schema = compile_fixture("schema.proto").expect("fixture schema compiles");
    let descriptor_set = &schema.file_descriptor_set;
    let decoded = prost_types::FileDescriptorSet::decode(schema.raw_descriptor_set.as_slice())
        .expect("raw descriptor set decodes as prost types");
    assert_eq!(&decoded, descriptor_set);

    let fixture_files = descriptor_set
        .file
        .iter()
        .filter(|file| file.name.as_deref() == Some("schema.proto"))
        .collect::<Vec<_>>();
    assert_eq!(fixture_files.len(), 1, "root descriptor occurs once");
    let fixture = fixture_files[0];
    assert_eq!(fixture.package.as_deref(), Some(FIXTURE_PACKAGE));
    assert_eq!(
        descriptor_set
            .file
            .iter()
            .filter(|file| file.name.as_deref() == Some("google/protobuf/descriptor.proto"))
            .count(),
        1,
        "imported descriptor occurs once"
    );
    assert!(
        fixture
            .source_code_info
            .as_ref()
            .is_some_and(|info| !info.location.is_empty()),
        "source information is retained"
    );

    let service = fixture
        .service
        .iter()
        .find(|service| service.name.as_deref() == Some("FixtureService"))
        .expect("fixture service is structurally represented");
    let method = service
        .method
        .first()
        .expect("fixture method is represented");
    assert_eq!(method.name.as_deref(), Some("Annotated"));
    assert_eq!(
        method.input_type.as_deref(),
        Some(".carbide.proto.compiler.fixture.Request")
    );
    assert_eq!(
        method.output_type.as_deref(),
        Some(".carbide.proto.compiler.fixture.Response")
    );

    let request = fixture
        .message_type
        .iter()
        .find(|message| message.name.as_deref() == Some("Request"))
        .expect("request message is structurally represented");
    let query = request.field.first().expect("request field is represented");
    assert_eq!(query.name.as_deref(), Some("query"));
    assert_eq!(query.number, Some(1));
    assert_eq!(
        query.r#type,
        Some(prost_types::field_descriptor_proto::Type::String as i32)
    );
    assert_eq!(query.proto3_optional, Some(true));
}

#[test]
fn raw_descriptor_pool_preserves_custom_option_values() {
    let schema = compile_fixture("schema.proto").expect("fixture schema compiles");
    let annotation = annotation(&schema.descriptor_pool);

    assert_eq!(
        annotation
            .get_field_by_name("enabled")
            .and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        annotation
            .get_field_by_name("limit")
            .and_then(|v| v.as_u32()),
        Some(73)
    );
    assert!(
        annotation
            .get_field_by_name("label")
            .is_some_and(|value| value.as_str() == Some("raw-option-sentinel"))
    );
}

#[test]
fn prost_reencoding_drops_custom_option_values() {
    let schema = compile_fixture("schema.proto").expect("fixture schema compiles");
    let reencoded = schema.file_descriptor_set.encode_to_vec();
    let reencoded_pool =
        DescriptorPool::decode(reencoded.as_slice()).expect("prost descriptor set decodes");

    let extension = reencoded_pool
        .get_extension_by_name(OPTION_NAME)
        .expect("extension declaration remains represented");
    let service = reencoded_pool
        .get_service_by_name(&format!("{FIXTURE_PACKAGE}.FixtureService"))
        .expect("fixture service remains represented");
    let method = service
        .methods()
        .find(|method| method.name() == "Annotated")
        .expect("fixture method remains represented");

    assert!(
        annotation(&schema.descriptor_pool)
            .get_field_by_name("enabled")
            .is_some()
    );
    assert!(
        !method.options().has_extension(&extension),
        "prost_types cannot retain unknown custom option values"
    );
    assert_ne!(schema.raw_descriptor_set, reencoded);
}

#[test]
fn malformed_protobuf_returns_typed_compilation_error() {
    let error = compile_fixture("malformed.proto").expect_err("malformed fixture must fail");
    assert!(matches!(error, Error::CompileProtobuf { .. }));
}
