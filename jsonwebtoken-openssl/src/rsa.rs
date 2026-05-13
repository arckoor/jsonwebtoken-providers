use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, EncodingKey,
    crypto::{JwtSigner, JwtVerifier},
    errors::{ErrorKind, Result, new_error},
    signature::{Error, Signer, Verifier},
};
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::{Padding, Rsa},
    sign::{Signer as OpenSSLSigner, Verifier as OpenSSLVerifier},
};

macro_rules! define_rsa_signer {
    ($name:ident, $alg:expr, $digest:expr, $padding:expr) => {
        pub struct $name(PKey<Private>);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family() != AlgorithmFamily::Rsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    PKey::private_key_from_der(encoding_key.inner())
                        .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?,
                ))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let mut signer =
                    OpenSSLSigner::new($digest, &self.0).map_err(Error::from_source)?;
                signer
                    .set_rsa_padding($padding)
                    .map_err(Error::from_source)?;
                signer.sign_oneshot_to_vec(&msg).map_err(Error::from_source)
            }
        }

        impl JwtSigner for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

macro_rules! define_rsa_verifier {
    ($name:ident, $alg:expr, $digest:expr, $padding:expr) => {
        pub struct $name(PKey<Public>);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Rsa {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                let rsa_key = Rsa::public_key_from_der_pkcs1(decoding_key.as_bytes())
                    .map_err(|e| ErrorKind::InvalidRsaKey(e.to_string()))?;
                let k = PKey::from_rsa(rsa_key).map_err(Error::from_source)?;

                Ok(Self(k))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                let mut verifier =
                    OpenSSLVerifier::new($digest, &self.0).map_err(Error::from_source)?;
                verifier
                    .set_rsa_padding($padding)
                    .map_err(Error::from_source)?;
                verifier
                    .verify_oneshot(signature, msg)
                    .map_err(Error::from_source)?
                    .then_some(())
                    .ok_or(Error::new())
            }
        }

        impl JwtVerifier for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

define_rsa_signer!(
    Rsa256Signer,
    Algorithm::RS256,
    MessageDigest::sha256(),
    Padding::PKCS1
);
define_rsa_signer!(
    Rsa384Signer,
    Algorithm::RS384,
    MessageDigest::sha384(),
    Padding::PKCS1
);
define_rsa_signer!(
    Rsa512Signer,
    Algorithm::RS512,
    MessageDigest::sha512(),
    Padding::PKCS1
);
define_rsa_signer!(
    RsaPss256Signer,
    Algorithm::PS256,
    MessageDigest::sha256(),
    Padding::PKCS1_PSS
);
define_rsa_signer!(
    RsaPss384Signer,
    Algorithm::PS384,
    MessageDigest::sha384(),
    Padding::PKCS1_PSS
);
define_rsa_signer!(
    RsaPss512Signer,
    Algorithm::PS512,
    MessageDigest::sha512(),
    Padding::PKCS1_PSS
);

define_rsa_verifier!(
    Rsa256Verifier,
    Algorithm::RS256,
    MessageDigest::sha256(),
    Padding::PKCS1
);
define_rsa_verifier!(
    Rsa384Verifier,
    Algorithm::RS384,
    MessageDigest::sha384(),
    Padding::PKCS1
);
define_rsa_verifier!(
    Rsa512Verifier,
    Algorithm::RS512,
    MessageDigest::sha512(),
    Padding::PKCS1
);

define_rsa_verifier!(
    RsaPss256Verifier,
    Algorithm::PS256,
    MessageDigest::sha256(),
    Padding::PKCS1_PSS
);
define_rsa_verifier!(
    RsaPss384Verifier,
    Algorithm::PS384,
    MessageDigest::sha384(),
    Padding::PKCS1_PSS
);
define_rsa_verifier!(
    RsaPss512Verifier,
    Algorithm::PS512,
    MessageDigest::sha512(),
    Padding::PKCS1_PSS
);
