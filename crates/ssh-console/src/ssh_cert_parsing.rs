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
use russh::keys::Certificate;

use crate::config::{CertAuthorization, CertAuthorizationStrategy, KeyIdFormat};

/// Search for the given role in the Key ID field of a certificate, returning if it is declared.
pub fn certificate_contains_role(
    certificate: &Certificate,
    role: &str,
    cert_authorization: &CertAuthorization,
) -> bool {
    for strategy in &cert_authorization.strategy {
        match strategy {
            CertAuthorizationStrategy::KeyId => {
                if key_id_contains_role(
                    certificate.key_id(),
                    role,
                    &cert_authorization.keyid_format,
                ) {
                    return true;
                }
            }
        }
    }

    false
}

/// Try to get the username from the given certificate, or return None if we couldn't find one.
pub fn get_user_from_certificate<'a>(
    certificate: &'a Certificate,
    cert_authorization: &CertAuthorization,
) -> Option<&'a str> {
    if let Some(principal) = certificate.valid_principals().first() {
        return Some(principal.as_str());
    }
    for strategy in &cert_authorization.strategy {
        match strategy {
            CertAuthorizationStrategy::KeyId => {
                if let Some(user) =
                    get_user_from_key_id(certificate.key_id(), &cert_authorization.keyid_format)
                {
                    return Some(user);
                }
            }
        }
    }

    None
}

fn key_id_contains_role(key_id: &str, role: &str, key_id_format: &KeyIdFormat) -> bool {
    // Example:
    //     group=some-group user=some-user roles=role1,role2,role3
    let Some(roles_attr) = key_id
        .split(&key_id_format.field_separator)
        .find_map(|field| {
            field.split_once('=').and_then(|(k, v)| {
                if k == key_id_format.role_field {
                    Some(v)
                } else {
                    None
                }
            })
        })
    else {
        tracing::warn!(
            "Could not find `{}=` substring in key_id: {:?}",
            key_id_format.role_field,
            key_id,
        );
        return false;
    };

    roles_attr
        .split(&key_id_format.role_separator)
        .any(|k| k == role)
}

fn get_user_from_key_id<'a>(key_id: &'a str, key_id_format: &KeyIdFormat) -> Option<&'a str> {
    // Example:
    //     group=some-group user=some-user roles=role1,role2,role3
    let Some(user) = key_id
        .split(&key_id_format.field_separator)
        .find_map(|field| {
            field.split_once('=').and_then(|(k, v)| {
                if k == key_id_format.user_field {
                    Some(v)
                } else {
                    None
                }
            })
        })
    else {
        tracing::warn!(
            "Could not find `{}=` substring in key_id: {:?}",
            key_id_format.user_field,
            key_id
        );
        return None;
    };

    Some(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_user_from_key_id() {
        let key_id = "group=group1 user=ksimon roles=role1,role2,role3";
        let parsed_user = get_user_from_key_id(
            key_id,
            &KeyIdFormat {
                field_separator: " ".to_string(),
                user_field: "user".to_string(),
                role_field: "roles".to_string(),
                role_separator: ",".to_string(),
            },
        );
        assert_eq!(parsed_user, Some("ksimon"));
    }

    #[test]
    fn test_key_id_contains_role() {
        let key_id = "group=group1 user=ksimon roles=role1,role2,role3";
        assert!(key_id_contains_role(
            key_id,
            "role1",
            &KeyIdFormat::default()
        ));
        assert!(key_id_contains_role(
            key_id,
            "role3",
            &KeyIdFormat::default()
        ));
        assert!(!key_id_contains_role(
            key_id,
            "fakerole",
            &KeyIdFormat::default()
        ));
    }

    #[test]
    fn test_key_id_contains_role_exact_match_not_substring() {
        // "role" should not match "role1"
        let key_id = "group=g user=u roles=role1,role2";
        assert!(!key_id_contains_role(
            key_id,
            "role",
            &KeyIdFormat::default()
        ));
        assert!(key_id_contains_role(
            key_id,
            "role2",
            &KeyIdFormat::default()
        ));
    }

    #[test]
    fn test_key_id_contains_role_missing_roles_field() {
        let key_id = "group=g user=u";
        assert!(!key_id_contains_role(
            key_id,
            "role1",
            &KeyIdFormat::default()
        ));
    }

    #[test]
    fn test_key_id_contains_role_empty_roles_value() {
        let key_id = "group=g user=u roles=";
        assert!(!key_id_contains_role(
            key_id,
            "anything",
            &KeyIdFormat::default()
        ));
    }

    #[test]
    fn test_key_id_contains_role_trailing_separator() {
        // Trailing separator yields an empty last token; should still find existing roles.
        let key_id = "group=g user=u roles=role1,role2,";
        assert!(key_id_contains_role(
            key_id,
            "role1",
            &KeyIdFormat::default()
        ));
        assert!(key_id_contains_role(
            key_id,
            "role2",
            &KeyIdFormat::default()
        ));
        assert!(!key_id_contains_role(
            key_id,
            "role3",
            &KeyIdFormat::default()
        ));
    }

    #[test]
    fn test_key_id_contains_role_custom_role_separator() {
        // Roles separated by semicolons
        let key_id = "group=g user=u roles=alpha;beta;gamma";
        let fmt = KeyIdFormat {
            field_separator: " ".into(),
            user_field: "user".into(),
            role_field: "roles".into(),
            role_separator: ";".into(),
        };
        assert!(key_id_contains_role(key_id, "beta", &fmt));
        assert!(!key_id_contains_role(key_id, "delta", &fmt));
    }

    #[test]
    fn test_key_id_contains_role_custom_field_separator() {
        // Fields separated by '|'
        let key_id = "group=g|user=u|roles=a,b,c";
        let fmt = KeyIdFormat {
            field_separator: "|".into(),
            user_field: "user".into(),
            role_field: "roles".into(),
            role_separator: ",".into(),
        };
        assert!(key_id_contains_role(key_id, "b", &fmt));
    }

    #[test]
    fn test_key_id_contains_role_fields_any_order() {
        // Different field order should not matter
        let key_id = "roles=r1,r2 group=g user=u";
        assert!(key_id_contains_role(key_id, "r2", &KeyIdFormat::default()));
    }

    #[test]
    fn test_get_user_from_key_id_missing_user_field() {
        let key_id = "group=g roles=r1,r2";
        let parsed_user = get_user_from_key_id(key_id, &KeyIdFormat::default());
        assert_eq!(parsed_user, None);
    }

    #[test]
    fn test_get_user_from_key_id_custom_fields_and_separator() {
        let key_id = "tenant=acme|login=alice|scopes=read;write";
        let fmt = KeyIdFormat {
            field_separator: "|".into(),
            user_field: "login".into(),
            role_field: "scopes".into(),
            role_separator: ";".into(),
        };
        assert_eq!(get_user_from_key_id(key_id, &fmt), Some("alice"));
        assert!(key_id_contains_role(key_id, "write", &fmt));
    }

    #[test]
    fn test_get_user_from_key_id_with_extra_equals_in_value() {
        // Values may contain '='; split_once should still produce the correct (k, v)
        let key_id = "group=g user=alice=dev roles=r1,r2";
        assert_eq!(
            get_user_from_key_id(key_id, &KeyIdFormat::default()),
            Some("alice=dev")
        );
    }

    #[test]
    fn test_key_id_contains_role_duplicate_roles() {
        let key_id = "group=g user=u roles=dup,dup";
        assert!(key_id_contains_role(key_id, "dup", &KeyIdFormat::default()));
    }

    #[test]
    fn test_key_id_contains_role_unknown_role_field_name() {
        // Roles are under a different field name; default format should not find them
        let key_id = "group=g user=u permissions=a,b,c";
        assert!(!key_id_contains_role(key_id, "a", &KeyIdFormat::default()));

        // But with matching role_field it should work
        let fmt = KeyIdFormat {
            field_separator: " ".into(),
            user_field: "user".into(),
            role_field: "permissions".into(),
            role_separator: ",".into(),
        };
        assert!(key_id_contains_role(key_id, "a", &fmt));
    }
}
