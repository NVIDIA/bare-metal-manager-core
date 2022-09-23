use http::{header, HeaderMap, Request, Response};
use serde::{Deserialize, Serialize};
use tower_http::auth::AuthorizeRequest;

pub use jwt::{Algorithm, DecodingKey, KeySpec};

// This is intended to be hooked into tower-http's
// RequireAuthorizationLayer::custom() middleware layer.
#[derive(Clone)]
pub struct CarbideAuth {
    jwt_validator: jwt::TokenValidator,
    permissive_mode: bool,
}

impl CarbideAuth {
    pub fn new() -> Self {
        let jwt_validator = jwt::TokenValidator::new();
        let permissive_mode = false;

        Self {
            jwt_validator,
            permissive_mode,
        }
    }

    pub fn _add_jwt_key(
        &mut self,
        algorithm: Algorithm,
        key_spec: KeySpec,
        decoding_key: DecodingKey,
    ) {
        self.jwt_validator
            ._add_key(algorithm, key_spec, decoding_key);
    }

    pub fn set_permissive_mode(&mut self, mode: bool) {
        self.permissive_mode = mode;
    }

    fn try_jwt_validation(&self, headers: &HeaderMap) -> Result<CarbideAuthClaims, AuthError> {
        let auth_header = headers
            .get(header::AUTHORIZATION)
            .ok_or(AuthError::NoAuthHeader)?;

        let bearer_token = {
            //
            // auth_header is currently an http::HeaderValue, let's make
            // it stringy.
            let auth_header = auth_header
                .to_str()
                .map_err(|_| AuthError::UnparseableAuthHeader)?;

            let (auth_scheme, auth_credentials) = auth_header
                .split_once(' ')
                .ok_or(AuthError::UnparseableAuthHeader)?;

            // A bearer token is all we know how to deal with.
            (auth_scheme == "Bearer")
                .then_some(auth_credentials)
                .ok_or_else(|| AuthError::UnsupportedAuthType(String::from(auth_scheme)))?
        };

        self.jwt_validator.validate(bearer_token)
    }
}

impl<B> AuthorizeRequest<B> for CarbideAuth {
    type ResponseBody = tonic::body::BoxBody;

    fn authorize(&mut self, request: &mut Request<B>) -> Result<(), Response<Self::ResponseBody>> {
        let jwt_validation = self.try_jwt_validation(request.headers());

        use std::convert::TryInto;
        let mut request_auth =
            authorization::RequestAuth::new(jwt_validation.and_then(|claims| claims.try_into()));
        if self.permissive_mode {
            request_auth.set_permissive(self.permissive_mode);
        }

        // Any subsequent layers can retrieve this struct with something
        // like this:
        //
        // let request_auth: RequestAuth = request.extensions.get();

        request.extensions_mut().insert(request_auth);

        // We don't try to enforce anything here, so the layers under us
        // are responsible for doing their own authorization checks using
        // the RequestAuth extension we added.
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CarbideAuthClaims {
    aud: String,
    iss: String,
    sub: String,
    privilege: Option<String>,
    vpc: Option<String>,
}

pub mod authorization {
    use super::AuthError;
    use super::Request;

    #[derive(Debug, Clone)]
    pub enum Privilege {
        // The site admin level can do anything.
        SiteAdmin,
        // A VPC admin can do anything to a specific VPC.
        VpcAdmin(String),
        // TODO: almost certainly more things to fill in here
    }

    impl std::convert::TryFrom<super::CarbideAuthClaims> for Privilege {
        type Error = AuthError;

        fn try_from(value: super::CarbideAuthClaims) -> Result<Self, Self::Error> {
            let privilege = value.privilege.ok_or_else(|| {
                AuthError::InvalidJWTClaims("No 'privilege' field found in claims".into())
            })?;
            match privilege.as_str() {
                "site-admin" => Ok(Privilege::SiteAdmin),
                "vpc-admin" => match value.vpc {
                    Some(vpc) => Ok(Privilege::VpcAdmin(vpc)),
                    None => Err(AuthError::InvalidJWTClaims(
                        "No 'vpc' field found in claims with 'vpc-admin' privilege".into(),
                    )),
                },
                p => Err(AuthError::InvalidJWTClaims(format!(
                    "Unknown privilege '{p}'"
                ))),
            }
        }
    }

    #[derive(Debug, Clone)]
    #[allow(dead_code)] //TODO: remove this once auth is used
    pub enum PrivilegeRequirement {
        Require(Privilege),
        Unprivileged,
    }

    impl PrivilegeRequirement {
        // Enforce requirement against a request.
        #[allow(dead_code)] //TODO: remove this once auth is used
        pub fn authorize_request<B>(&self, request: &Request<B>) -> Result<(), AuthError> {
            let request_auth = request.extensions().get::<RequestAuth>();
            self.authorize(request_auth)
        }

        pub fn authorize(&self, request_auth: Option<&RequestAuth>) -> Result<(), AuthError> {
            let request_privilege: Option<&Privilege> =
                request_auth.and_then(|ra| ra.privs_result.as_ref().ok());
            let sufficient = self.can_accept(request_privilege);
            let permissive_mode = request_auth.map(|ra| ra.permissive);

            match (sufficient, permissive_mode) {
                // Normal happy path.
                (true, _) => Ok(()),

                // Insufficient permission level, but allowed under permissive
                // mode.
                (false, Some(true)) => {
                    log::info!(
                        "Request with insufficient authorization allowed due to permissive mode"
                    );
                    Ok(())
                }

                // Denied, insufficient privilege level.
                (false, _) => {
                    let reason = request_auth
                        .map(|ra| {
                            ra.privs_result.as_ref()
                                .map_or_else(
                                    |e: &AuthError| { format!("the request couldn't be authenticated: {e}") },
                                    |p: &Privilege| { format!("the request's privilege level ({p:?}) was insufficient") },
                                )
                        }
                        )
                        .unwrap_or_else(
                            || { String::from("no RequestAuth was found in this request's type map (this shouldn't happen!)") }
                        );
                    Err(AuthError::InsufficientPrivilegeLevel(format!(
                        "This operation requires a privilege level of {self:?}, but {reason}"
                    )))
                }
            }
        }

        pub fn can_accept(&self, privilege: Option<&Privilege>) -> bool {
            let req = match self {
                // Early return: an unprivileged operation can always work.
                PrivilegeRequirement::Unprivileged => return true,
                PrivilegeRequirement::Require(p) => p,
            };
            let privilege = match privilege {
                // Early return: we already handled the unprivileged case
                // above, so all remaining operations will be privileged,
                // which requires _some_ privilege provided to succeed.
                // Thus, a None will never be accepted here.
                None => return false,
                Some(p) => p,
            };

            match (req, privilege) {
                (_, Privilege::SiteAdmin) => true,
                (Privilege::VpcAdmin(vpc1), Privilege::VpcAdmin(vpc2)) if vpc1.as_str() == vpc2 => {
                    true
                }
                (_, _) => false,
            }
        }
    }

    // The auth context associated with a specific request, after JWT decoding
    // and whatever else.
    #[derive(Debug, Clone)]
    pub struct RequestAuth {
        privs_result: PrivilegeResult,
        permissive: bool,
    }

    impl RequestAuth {
        pub fn new(privs_result: PrivilegeResult) -> Self {
            RequestAuth {
                privs_result,
                permissive: false,
            }
        }

        pub fn set_permissive(&mut self, permissive: bool) {
            self.permissive = permissive;
        }
    }

    pub type PrivilegeResult = Result<Privilege, AuthError>;

    #[cfg(test)]
    mod test {
        use super::*;

        #[test]
        pub fn test_can_accept() {
            let privilege_requirement = PrivilegeRequirement::Unprivileged;
            assert!(privilege_requirement.can_accept(None));
        }

        #[test]
        pub fn test_authorization() {
            let privilege_requirement = PrivilegeRequirement::Unprivileged;
            privilege_requirement.authorize(None).unwrap();

            let privilege_requirement = PrivilegeRequirement::Require(Privilege::SiteAdmin);
            match privilege_requirement.authorize(None) {
                Err(AuthError::InsufficientPrivilegeLevel(_)) => {}
                _ => {
                    panic!("should have failed with insufficient privilege level");
                }
            }
        }

        #[test]
        pub fn test_authorize_request() {
            let request: Request<Vec<u8>> = Request::new(vec![]);
            let privilege_requirement = PrivilegeRequirement::Unprivileged;
            privilege_requirement.authorize_request(&request).unwrap();
        }
    }
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum AuthError {
    #[error("JWT error {0}")]
    JWTError(#[from] jsonwebtoken::errors::Error),

    #[error("JWT decode error {0}")]
    JWTDecodeError(jsonwebtoken::errors::Error),

    #[error("JWT-related placeholder error")]
    JWTFixmeError,

    #[error("Unknown signer key and algorithm pair")]
    UnrecognizedSigSpec,

    #[error("No HTTP Authorization header was found")]
    NoAuthHeader,

    #[error("Unparseable HTTP Authorization header")]
    UnparseableAuthHeader,

    #[error("Unsupported Authorization type {0}")]
    UnsupportedAuthType(String),

    #[error("Invalid JWT claims: {0}")]
    InvalidJWTClaims(String),

    #[error("Insufficient privilege level: {0}")]
    InsufficientPrivilegeLevel(String),
}

mod jwt {
    use std::collections::HashMap;

    use jsonwebtoken::{decode, decode_header, Validation};
    pub use jsonwebtoken::{Algorithm, DecodingKey};

    use super::{AuthError, CarbideAuthClaims};

    #[derive(Clone)]
    pub struct TokenValidator {
        validators: HashMap<TokenSigSpec, DecoderSpec>,
    }

    impl TokenValidator {
        pub fn new() -> Self {
            let validators = HashMap::new();
            Self { validators }
        }

        pub fn _add_key(
            &mut self,
            algorithm: Algorithm,
            key_spec: KeySpec,
            decoding_key: DecodingKey,
        ) {
            let sig_spec = TokenSigSpec {
                algorithm,
                key_spec,
            };
            let verification_spec = DecoderSpec {
                decoding_key,
                validation: Validation::new(algorithm),
            };
            _ = self.validators.insert(sig_spec, verification_spec);
        }

        pub fn validate(&self, token: &str) -> Result<CarbideAuthClaims, AuthError> {
            let header = decode_header(token).map_err(AuthError::JWTDecodeError)?;
            let algorithm = header.alg;
            let key_id = header.kid.ok_or(AuthError::JWTFixmeError)?;
            let token_sig_spec = TokenSigSpec {
                algorithm,
                key_spec: KeySpec::KeyID(key_id),
            };
            let decoder_spec = self
                .validators
                .get(&token_sig_spec)
                .ok_or(AuthError::UnrecognizedSigSpec)?;

            let decoded = decode::<CarbideAuthClaims>(
                token,
                &decoder_spec.decoding_key,
                &decoder_spec.validation,
            )
            .map_err(AuthError::JWTDecodeError)?;

            // big time FIXME: We aren't validating the iss/sub/aud fields,
            // since at the time of this writing there isn't anything specified
            // or agreed upon for what they should be. -db

            Ok(decoded.claims)
        }
    }

    #[derive(Clone, Eq, PartialEq, Hash)]
    pub struct TokenSigSpec {
        algorithm: Algorithm,
        key_spec: KeySpec,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Hash)]
    pub enum KeySpec {
        KeyID(String),
    }

    #[derive(Clone)]
    pub struct DecoderSpec {
        decoding_key: DecodingKey,
        validation: Validation,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_initialize() {
            let v = TokenValidator::new();
            assert!(matches!(v, TokenValidator { .. }));
        }

        #[test]
        fn test_parse_invalid() {
            let v = TokenValidator::new();
            let result = v.validate("this is not even a JWT");
            assert!(matches!(result, Err(AuthError::JWTDecodeError(_))));
            let result = v.validate("bleep.bloop.blup");
            assert!(matches!(result, Err(AuthError::JWTDecodeError(_))));
        }

        #[test]
        fn test_decode() {
            // base64 encoding of "this is not a very good secret"
            let b64_key = "dGhpcyBpcyBub3QgYSB2ZXJ5IGdvb2Qgc2VjcmV0";
            let decode_key = DecodingKey::from_base64_secret(b64_key).unwrap();

            let mut v = TokenValidator::new();
            v._add_key(
                Algorithm::HS256,
                KeySpec::KeyID("testing-kid".into()),
                decode_key,
            );

            // This JWT was made with the following Python (using PyJWT):
            // jwt.encode(
            //     dict(
            //         iss='test issuer',
            //         aud='test audience',
            //         sub='test subject',
            //         exp=int((datetime.datetime.utcnow() + datetime.timedelta(days = 365 * 10)).timestamp()),
            //     ),
            //     'this is not a very good secret',
            //     headers=dict(kid='testing-kid')
            // )
            let jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6InRlc3Rpbmcta2lkIn0.eyJpc3MiOiJ0ZXN0IGlzc3VlciIsImF1ZCI6InRlc3QgYXVkaWVuY2UiLCJzdWIiOiJ0ZXN0IHN1YmplY3QiLCJleHAiOjE5NzA3NjE1NDN9.wyGCEyEdWO47p60jgX_ITp27UPO8WEVC1LtlPNnNDw8";

            let claims = v.validate(jwt).unwrap();
            assert!(matches!(claims, CarbideAuthClaims { .. }));
            assert_eq!(
                claims,
                CarbideAuthClaims {
                    iss: "test issuer".into(),
                    aud: "test audience".into(),
                    sub: "test subject".into(),
                    privilege: None,
                    vpc: None,
                }
            );
        }
    }
}
