use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, EncodingKey,
    crypto::{JwtSigner, JwtVerifier},
    errors::{ErrorKind, Result, new_error},
    signature::{Error, Signer, Verifier},
};
use openssl::{
    hash::MessageDigest,
    pkey::{Id, PKey, Private, Public},
    sign::{Signer as OpenSSLSigner, Verifier as OpenSSLVerifier},
};

pub struct EdDSASigner(PKey<Private>);

impl EdDSASigner {
    pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
        if encoding_key.family() != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            PKey::private_key_from_der(encoding_key.inner())
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ))
    }
}

impl Signer<Vec<u8>> for EdDSASigner {
    fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let mut signer =
            OpenSSLSigner::new(MessageDigest::null(), &self.0).map_err(Error::from_source)?;
        signer.sign_oneshot_to_vec(msg).map_err(Error::from_source)
    }
}

impl JwtSigner for EdDSASigner {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}

pub struct EdDSAVerifier(PKey<Public>);

impl EdDSAVerifier {
    pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
        if decoding_key.family() != AlgorithmFamily::Ed {
            return Err(new_error(ErrorKind::InvalidKeyFormat));
        }

        Ok(Self(
            PKey::public_key_from_raw_bytes(decoding_key.as_bytes(), Id::ED25519)
                .map_err(|_| ErrorKind::InvalidEddsaKey)?,
        ))
    }
}

impl Verifier<Vec<u8>> for EdDSAVerifier {
    fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
        let mut verifier =
            OpenSSLVerifier::new(MessageDigest::null(), &self.0).map_err(Error::from_source)?;
        verifier
            .verify_oneshot(signature, msg)
            .map_err(Error::from_source)?
            .then_some(())
            .ok_or(Error::new())
    }
}

impl JwtVerifier for EdDSAVerifier {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }
}
