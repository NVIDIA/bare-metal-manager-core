use std::collections::HashSet;

use http::{header, HeaderMap, Request, Response, StatusCode, Uri};
use log::info;
use serde::{Deserialize, Serialize};
use tower_http::auth::AuthorizeRequest;

pub use jwt::{Algorithm, DecodingKey, KeySpec};

// This is intended to be hooked into tower-http's
// RequireAuthorizationLayer::custom() middleware layer.
#[derive(Clone)]
pub struct CarbideAuth {
    unsecured_endpoints: HashSet<Uri>,
    jwt_validator: jwt::TokenValidator,
    permissive_mode: bool,
}

impl CarbideAuth {
    pub fn new() -> Self {
        let unsecured_endpoints = HashSet::new();
        let jwt_validator = jwt::TokenValidator::new();
        let permissive_mode = false;

        Self {
            unsecured_endpoints,
            jwt_validator,
            permissive_mode,
        }
    }

    pub fn add_jwt_key(&mut self, algorithm: Algorithm, key_spec: KeySpec, decoding_key: DecodingKey) {
        self.jwt_validator
            .add_key(algorithm, key_spec, decoding_key);
    }

    pub fn add_unsecured_endpoint(&mut self, endpoint: Uri) {
        self.unsecured_endpoints.insert(endpoint);
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
                .then(|| auth_credentials)
                .ok_or(AuthError::UnsupportedAuthType(String::from(auth_scheme)))?
        };

        self.jwt_validator.validate(bearer_token)
    }
}

impl<B> AuthorizeRequest<B> for CarbideAuth {
    type ResponseBody = tonic::body::BoxBody;

    fn authorize(&mut self, request: &mut Request<B>) -> Result<(), Response<Self::ResponseBody>> {
        let unsecured_endpoint = self.unsecured_endpoints.contains(request.uri());

        let jwt_validation = self.try_jwt_validation(request.headers());

        match (jwt_validation, unsecured_endpoint) {
            // If we've validated the claims, we can proceed regardless
            // of the status of the endpoint in the request.
            (Ok(claims), _) => {
                // Any subsequent layers can retrieve this claims struct
                // with something like this:
                //
                // let claims: CarbideAuthClaims = request.extensions.get();
                request.extensions_mut().insert(claims);

                Ok(())
            }

            (Err(_), true) => {
                // Authentication failed, but this request's endpoint allows
                // unauthenticated requests.

                Ok(())
            }

            (Err(e), false) => {
                info!("Request authentication failed: {:?}", e);

                if self.permissive_mode {
                    info!("Request allowed due to permissive mode");
                    return Ok(())
                }

                let unauthorized = Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(tonic::body::empty_body())
                    .unwrap();

                Err(unauthorized)
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CarbideAuthClaims {
    // FIXME: Fill this out more, aud/iss/sub are probably not sufficient to
    // represent our permissions.
    aud: String,
    iss: String,
    sub: String,
}

#[allow(dead_code)]
pub mod authorization {

    #[derive(Debug, Clone)]
    pub enum Privilege {
        // The site admin level can do anything.
        SiteAdmin,
        // A VPC admin can do anything to a specific VPC.
        VpcAdmin(String),
        // TODO: almost certainly more things to fill in here
    }

}


#[derive(thiserror::Error, Debug)]
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
}

mod jwt {

    pub use jsonwebtoken::{Algorithm, DecodingKey};

    use super::{AuthError, CarbideAuthClaims};

    use jsonwebtoken::{decode, decode_header, Validation};
    use std::collections::HashMap;

    #[derive(Clone)]
    pub struct TokenValidator {
        validators: HashMap<TokenSigSpec, DecoderSpec>,
    }

    impl TokenValidator {
        pub fn new() -> Self {
            let validators = HashMap::new();
            Self { validators }
        }

        pub fn add_key(
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
            let header = decode_header(token).map_err(|e| AuthError::JWTDecodeError(e))?;
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
            .map_err(|e| AuthError::JWTDecodeError(e))?;

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
            let decode_key = DecodingKey::from_base64_secret(&b64_key).unwrap();

            let mut v = TokenValidator::new();
            v.add_key(
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

            let claims = v.validate(&jwt).unwrap();
            assert!(matches!(claims, CarbideAuthClaims { .. }));
            assert_eq!(
                claims,
                CarbideAuthClaims {
                    iss: "test issuer".into(),
                    aud: "test audience".into(),
                    sub: "test subject".into(),
                }
            );
        }
    }
}
