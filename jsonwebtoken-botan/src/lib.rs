//! A [`CryptoProvider`] for [jsonwebtoken], backed by [Botan](https://github.com/randombit/botan) (via [botan]).

#![deny(missing_docs)]

use botan::{HashFunction, Privkey, Pubkey};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey,
    crypto::{CryptoProvider, JwtSigner, JwtVerifier, KeyUtils},
    errors::{self, Error, ErrorKind},
    jwk::{EllipticCurve, ThumbprintHash},
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
        _ => return Err(ErrorKind::UnsupportedAlgorithm.into()),
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
        _ => return Err(ErrorKind::UnsupportedAlgorithm.into()),
    };

    Ok(jwt_verifier)
}

fn rsa_pub_components_from_private_key(key_content: &[u8]) -> errors::Result<(Vec<u8>, Vec<u8>)> {
    let privkey =
        Privkey::load_rsa_pkcs1(key_content).map_err(|e| ErrorKind::Provider(e.to_string()))?;
    let n = privkey
        .get_field("n")
        .map_err(|e| ErrorKind::Provider(e.to_string()))?
        .to_bin()
        .map_err(|e| ErrorKind::Provider(e.to_string()))?;
    let e = privkey
        .get_field("e")
        .map_err(|e| ErrorKind::Provider(e.to_string()))?
        .to_bin()
        .map_err(|e| ErrorKind::Provider(e.to_string()))?;
    Ok((n, e))
}
fn rsa_pub_components_from_public_key(key_content: &[u8]) -> errors::Result<(Vec<u8>, Vec<u8>)> {
    let pubkey =
        Pubkey::load_rsa_pkcs1(key_content).map_err(|e| ErrorKind::Provider(e.to_string()))?;
    let n = pubkey
        .get_field("n")
        .map_err(|e| ErrorKind::Provider(e.to_string()))?
        .to_bin()
        .map_err(|e| ErrorKind::Provider(e.to_string()))?;
    let e = pubkey
        .get_field("e")
        .map_err(|e| ErrorKind::Provider(e.to_string()))?
        .to_bin()
        .map_err(|e| ErrorKind::Provider(e.to_string()))?;
    Ok((n, e))
}

fn ec_pub_components_from_private_key(
    key_content: &[u8],
    alg: Algorithm,
) -> errors::Result<(EllipticCurve, Vec<u8>, Vec<u8>)> {
    let privkey = Privkey::load_der(key_content).map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    let x = privkey
        .get_field("public_x")
        .map_err(|e| ErrorKind::Provider(e.to_string()))?
        .to_bin()
        .map_err(|e| ErrorKind::Provider(e.to_string()))?;
    let y = privkey
        .get_field("public_y")
        .map_err(|e| ErrorKind::Provider(e.to_string()))?
        .to_bin()
        .map_err(|e| ErrorKind::Provider(e.to_string()))?;

    match alg {
        Algorithm::ES256 => Ok((EllipticCurve::P256, x, y)),
        Algorithm::ES384 => Ok((EllipticCurve::P384, x, y)),
        _ => Err(ErrorKind::InvalidEcdsaKey.into()),
    }
}

fn ed_pub_components_from_private_key(
    key_content: &[u8],
    curve_type: &EllipticCurve,
) -> errors::Result<Vec<u8>> {
    match curve_type {
        EllipticCurve::Ed25519 => {
            let private_key =
                Privkey::load_der(key_content).map_err(|_| ErrorKind::InvalidEddsaKey)?;
            Ok(private_key
                .pubkey()
                .map_err(|e| ErrorKind::Provider(e.to_string()))?
                .raw_bytes()
                .map_err(|e| ErrorKind::Provider(e.to_string()))?)
        }

        _ => Err(ErrorKind::InvalidAlgorithm.into()),
    }
}

fn compute_digest(data: &[u8], hash_function: ThumbprintHash) -> errors::Result<Vec<u8>> {
    let algo = match hash_function {
        ThumbprintHash::SHA256 => "SHA-256",
        ThumbprintHash::SHA384 => "SHA-384",
        ThumbprintHash::SHA512 => "SHA-512",
        _ => return Err(ErrorKind::UnsupportedAlgorithm.into()),
    };

    let mut hash_function =
        HashFunction::new(algo).map_err(|e| ErrorKind::Provider(e.to_string()))?;
    hash_function
        .update(data)
        .map_err(|e| ErrorKind::Provider(e.to_string()))?;
    Ok(hash_function
        .finish()
        .map_err(|e| ErrorKind::Provider(e.to_string()))?)
}

/// A [Botan](https://github.com/randombit/botan) backed [`CryptoProvider`].
pub static DEFAULT_PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: new_signer,
    verifier_factory: new_verifier,
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key,
        rsa_pub_components_from_public_key,
        ec_pub_components_from_private_key,
        ed_pub_components_from_private_key,
        compute_digest,
    },
};

/// Install the [Botan](https://github.com/randombit/botan) backed [`CryptoProvider`].
pub fn install_default() -> Result<(), &'static CryptoProvider> {
    DEFAULT_PROVIDER.install_default()
}
