use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, EncodingKey,
    crypto::{JwtSigner, JwtVerifier},
    errors::{ErrorKind, Result, new_error},
    signature::{Error, Signer, Verifier},
};
use openssl::{
    hash::MessageDigest,
    memcmp,
    pkey::{PKey, Private},
    sign::Signer as OpenSSLSigner,
};

macro_rules! define_hmac_signer {
    ($name:ident, $alg:expr, $digest:expr) => {
        pub struct $name(PKey<Private>);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family() != AlgorithmFamily::Hmac {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    PKey::hmac(encoding_key.try_get_hmac_secret()?).map_err(Error::from_source)?,
                ))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let mut signer =
                    OpenSSLSigner::new($digest, &self.0).map_err(Error::from_source)?;
                signer.update(msg).map_err(Error::from_source)?;
                signer.sign_to_vec().map_err(Error::from_source)
            }
        }

        impl JwtSigner for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

macro_rules! define_hmac_verifier {
    ($name:ident, $alg:expr, $digest:expr) => {
        pub struct $name(PKey<Private>);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Hmac {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    PKey::hmac(decoding_key.try_get_hmac_secret()?).map_err(Error::from_source)?,
                ))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                let mut signer =
                    OpenSSLSigner::new($digest, &self.0).map_err(Error::from_source)?;
                memcmp::eq(
                    &signer
                        .sign_oneshot_to_vec(msg)
                        .map_err(Error::from_source)?,
                    signature,
                )
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

define_hmac_signer!(Hs256Signer, Algorithm::HS256, MessageDigest::sha256());
define_hmac_signer!(Hs384Signer, Algorithm::HS384, MessageDigest::sha384());
define_hmac_signer!(Hs512Signer, Algorithm::HS512, MessageDigest::sha512());

define_hmac_verifier!(Hs256Verifier, Algorithm::HS256, MessageDigest::sha256());
define_hmac_verifier!(Hs384Verifier, Algorithm::HS384, MessageDigest::sha384());
define_hmac_verifier!(Hs512Verifier, Algorithm::HS512, MessageDigest::sha512());
