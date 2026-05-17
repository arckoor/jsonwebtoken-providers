use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, EncodingKey,
    crypto::{JwtSigner, JwtVerifier},
    errors::{ErrorKind, Result, new_error},
    signature::{Error, Signer, Verifier},
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    sign::{Signer as OpenSSLSigner, Verifier as OpenSSLVerifier},
};

fn extract_points(bytes: &[u8], point_length: usize) -> Result<(BigNum, BigNum)> {
    if bytes.len() != 1 + 2 * point_length || bytes[0] != 4 {
        return Err(ErrorKind::InvalidEcdsaKey.into());
    }

    let x_bytes =
        BigNum::from_slice(&bytes[1..point_length + 1]).map_err(|_| ErrorKind::InvalidEcdsaKey)?;
    let y_bytes = BigNum::from_slice(&bytes[point_length + 1..point_length * 2 + 1])
        .map_err(|_| ErrorKind::InvalidEcdsaKey)?;

    Ok((x_bytes, y_bytes))
}

macro_rules! define_ecdsa_signer {
    ($name:ident, $alg:expr, $point_length:expr, $digest:expr) => {
        pub struct $name(PKey<Private>);

        impl $name {
            pub(crate) fn new(encoding_key: &EncodingKey) -> Result<Self> {
                if encoding_key.family() != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                Ok(Self(
                    PKey::private_key_from_der(encoding_key.inner())
                        .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                ))
            }
        }

        impl Signer<Vec<u8>> for $name {
            fn try_sign(&self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
                let mut signer =
                    OpenSSLSigner::new($digest, &self.0).map_err(Error::from_source)?;
                let der = signer
                    .sign_oneshot_to_vec(msg)
                    .map_err(Error::from_source)?;

                let sig = EcdsaSig::from_der(&der).map_err(Error::from_source)?;

                let r = sig
                    .r()
                    .to_vec_padded($point_length)
                    .map_err(Error::from_source)?;
                let s = sig
                    .s()
                    .to_vec_padded($point_length)
                    .map_err(Error::from_source)?;

                Ok([r, s].concat())
            }
        }

        impl JwtSigner for $name {
            fn algorithm(&self) -> Algorithm {
                $alg
            }
        }
    };
}

macro_rules! define_ecdsa_verifier {
    ($name:ident, $alg:expr, $nid:expr, $point_length:expr, $digest:expr) => {
        pub struct $name(PKey<Public>);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                let group = EcGroup::from_curve_name($nid).map_err(Error::from_source)?;
                let (x_bytes, y_bytes) = extract_points(decoding_key.as_bytes(), $point_length)?;
                Ok(Self(
                    PKey::from_ec_key(
                        EcKey::from_public_key_affine_coordinates(&group, &x_bytes, &y_bytes)
                            .map_err(|_| ErrorKind::InvalidEcdsaKey)?,
                    )
                    .map_err(Error::from_source)?,
                ))
            }
        }

        impl Verifier<Vec<u8>> for $name {
            fn verify(&self, msg: &[u8], signature: &Vec<u8>) -> std::result::Result<(), Error> {
                if signature.len() != 2 * $point_length {
                    return Err(Error::new());
                }

                let r =
                    BigNum::from_slice(&signature[..$point_length]).map_err(Error::from_source)?;
                let s =
                    BigNum::from_slice(&signature[$point_length..]).map_err(Error::from_source)?;

                let der = EcdsaSig::from_private_components(r, s)
                    .map_err(Error::from_source)?
                    .to_der()
                    .map_err(Error::from_source)?;

                let mut verifier =
                    OpenSSLVerifier::new($digest, &self.0).map_err(Error::from_source)?;
                verifier
                    .verify_oneshot(&der, msg)
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

define_ecdsa_signer!(Es256Signer, Algorithm::ES256, 32, MessageDigest::sha256());
define_ecdsa_signer!(Es384Signer, Algorithm::ES384, 48, MessageDigest::sha384());

define_ecdsa_verifier!(
    Es256Verifier,
    Algorithm::ES256,
    Nid::X9_62_PRIME256V1,
    32,
    MessageDigest::sha256()
);

define_ecdsa_verifier!(
    Es384Verifier,
    Algorithm::ES384,
    Nid::SECP384R1,
    48,
    MessageDigest::sha384()
);
