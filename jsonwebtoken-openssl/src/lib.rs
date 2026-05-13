use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey,
    crypto::{CryptoProvider, JwkUtils, JwtSigner, JwtVerifier},
    errors::Error,
};

mod ecdsa;
mod eddsa;
mod hmac;
mod rsa;

fn new_signer(algorithm: &Algorithm, key: &EncodingKey) -> Result<Box<dyn JwtSigner>, Error> {
    let jwt_signer = match algorithm {
        Algorithm::HS256 => Box::new(hmac::Hs256Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::HS384 => Box::new(hmac::Hs384Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::HS512 => Box::new(hmac::Hs512Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::ES256 => Box::new(ecdsa::Es256Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::ES384 => Box::new(ecdsa::Es384Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::RS256 => Box::new(rsa::Rsa256Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::RS384 => Box::new(rsa::Rsa384Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::RS512 => Box::new(rsa::Rsa512Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::PS256 => Box::new(rsa::RsaPss256Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::PS384 => Box::new(rsa::RsaPss384Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::PS512 => Box::new(rsa::RsaPss512Signer::new(key)?) as Box<dyn JwtSigner>,
        Algorithm::EdDSA => Box::new(eddsa::EdDSASigner::new(key)?) as Box<dyn JwtSigner>,
    };
    Ok(jwt_signer)
}

fn new_verifier(algorithm: &Algorithm, key: &DecodingKey) -> Result<Box<dyn JwtVerifier>, Error> {
    let jwt_verifier = match algorithm {
        Algorithm::HS256 => Box::new(hmac::Hs256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::HS384 => Box::new(hmac::Hs384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::HS512 => Box::new(hmac::Hs512Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::ES256 => Box::new(ecdsa::Es256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::ES384 => Box::new(ecdsa::Es384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::RS256 => Box::new(rsa::Rsa256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::RS384 => Box::new(rsa::Rsa384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::RS512 => Box::new(rsa::Rsa512Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::PS256 => Box::new(rsa::RsaPss256Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::PS384 => Box::new(rsa::RsaPss384Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::PS512 => Box::new(rsa::RsaPss512Verifier::new(key)?) as Box<dyn JwtVerifier>,
        Algorithm::EdDSA => Box::new(eddsa::EdDSAVerifier::new(key)?) as Box<dyn JwtVerifier>,
    };

    Ok(jwt_verifier)
}

pub static DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: new_signer,
    verifier_factory: new_verifier,
    jwk_utils: JwkUtils::new_unimplemented(),
};

pub fn install_default() -> Result<(), &'static CryptoProvider> {
    DEFAULT_PROVIDER.install_default()
}
