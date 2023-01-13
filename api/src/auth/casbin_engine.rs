/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::error;
use std::path::{Path, PathBuf};

use crate::auth::{Action, Authorization, AuthorizationError, Object, PolicyEngine, Principal};

use casbin::{CoreApi, DefaultModel, Enforcer, FileAdapter};

pub enum ModelType {
    BasicAcl,
}

pub struct CasbinEngine {
    inner: Enforcer,
}

impl CasbinEngine {
    pub async fn new(
        model_type: ModelType,
        policy_path: &Path,
    ) -> Result<Self, Box<dyn error::Error>> {
        let model = match model_type {
            ModelType::BasicAcl => build_acl_model().await,
        };
        let policy_path = PathBuf::from(policy_path);
        let adapter = FileAdapter::new(policy_path);
        let enforcer = Enforcer::new(model, adapter).await?;
        Ok(CasbinEngine { inner: enforcer })
    }
}

impl PolicyEngine for CasbinEngine {
    fn authorize(
        &self,
        principals: &[Principal],
        action: Action,
        object: Object,
    ) -> Result<Authorization, AuthorizationError> {
        let cas_action = action.as_str();
        let cas_object = object.as_str();
        let mut principals = Vec::from(principals);

        // Make sure we always check anonymous access as a last resort.
        principals.push(Principal::Anonymous);

        let enforcer = &self.inner;

        let auth_result = principals
            .iter()
            .find(|principal| {
                let cas_subject = principal.as_identifier();
                // Casbin doesn't type these very strongly; be careful
                // they're in the correct order:
                let sub_obj_act = (cas_subject, cas_object, cas_action);
                match enforcer.enforce(sub_obj_act) {
                    Ok(true) => true,
                    Ok(false) => {
                        log::debug!("CasbinEngine: denied (principal={principal:?}, object={object:?}, action={action:?})");
                        false
                    }
                    Err(e) => {
                        log::error!("CasbinEngine: error from enforcer: {e}");
                        false
                    }
                }
            })
            .map(|principal| Authorization {
                principal: principal.clone(),
                action,
                object,
            })
            .ok_or_else(|| {
                let reason = format!(
                    "CasbinEngine: all auth principals denied by enforcer \
                    (object={object:?}, action={action:?}, principals={principals:?})"
                );
                AuthorizationError::Unauthorized(reason)
                }
            );

        if let Ok(authorization) = auth_result.as_ref() {
            log::debug!("CasbinEngine: authorized with {authorization:?}");
        }

        auth_result
    }
}

async fn build_acl_model() -> DefaultModel {
    // TODO: Is it possible to build this using the inscrutable .add_def()
    // method of DefaultModel? That seems to be what from_str() is implemented
    // on top of.
    DefaultModel::from_str(MODEL_CONFIG_ACL)
        .await
        .expect("Could not load ACL model")
}

// This is the "basic model" from the supported models, aka "ACL without superuser".
const MODEL_CONFIG_ACL: &str = r#"
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"#;
