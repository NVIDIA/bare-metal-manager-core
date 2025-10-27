/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use casbin::{CoreApi, DefaultModel, Enforcer, FileAdapter};

use crate::auth::{Authorization, AuthorizationError, PolicyEngine, Predicate, Principal};

pub enum ModelType {
    // Basic ACL with three arguments (subject, action, object)
    _BasicAcl,

    // A custom model that does RBAC on (subject, action) with glob matching
    // on the action.
    Rbac,
}

pub struct CasbinEngine {
    inner: Enforcer,
}

impl CasbinEngine {
    pub async fn new(
        model_type: ModelType,
        policy_path: &Path,
    ) -> Result<Self, Box<dyn error::Error>> {
        let model = build_model(model_type).await;
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
        predicate: Predicate,
    ) -> Result<Authorization, AuthorizationError> {
        let enforcer = &self.inner;

        // We move the predicate into the Authorization later, so let's record a
        // printable version of it up front for our logging needs.
        let dbg_predicate = format!("{:?}", &predicate);

        let auth_result = principals
            .iter()
            .find(|principal| {
                let cas_subject = principal.as_identifier();
                // Casbin is pretty stringly-typed under the hood. Be careful
                // that what we're passing in here matches the order that the
                // model and policy use.
                let enforce_result = match &predicate {
                    Predicate::ForgeCall(method) => {
                        let forge_call = format!("forge/{method}");
                        enforcer.enforce((cas_subject, forge_call))
                    }
                };
                match enforce_result {
                    Ok(true) => true,
                    Ok(false) => {
                        tracing::debug!(?principal, ?dbg_predicate, "CasbinEngine: denied");
                        false
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "CasbinEngine: error from enforcer");
                        false
                    }
                }
            })
            .map(|principal| Authorization {
                _principal: principal.clone(),
                _predicate: predicate,
            })
            .ok_or(AuthorizationError::Unauthorized);

        if let Ok(authorization) = auth_result.as_ref() {
            tracing::debug!(?authorization, "CasbinEngine: authorized");
        }

        auth_result
    }
}

async fn build_model(model_type: ModelType) -> DefaultModel {
    // TODO: Is it possible to build this using the inscrutable .add_def()
    // method of DefaultModel? That seems to be what from_str() is implemented
    // on top of.
    let policy_config = match model_type {
        ModelType::_BasicAcl => MODEL_CONFIG_ACL,
        ModelType::Rbac => MODEL_CONFIG_RBAC,
    };
    DefaultModel::from_str(policy_config)
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

const MODEL_CONFIG_RBAC: &str = r#"
[request_definition]
r = sub, act

[policy_definition]
p = sub, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && globMatch(r.act, p.act)
"#;
