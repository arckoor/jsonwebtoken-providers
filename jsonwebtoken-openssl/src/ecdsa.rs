use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, EncodingKey,
    crypto::{JwtSigner, JwtVerifier},
    errors::{ErrorKind, Result, new_error},
    signature::{Error, Signer, Verifier},
};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private, Public},
    sign::{Signer as OpenSSLSigner, Verifier as OpenSSLVerifier},
};

fn extract_points(bytes: &[u8], curve: Nid) -> Result<(BigNum, BigNum)> {
    let point_length = match curve {
        Nid::X9_62_PRIME256V1 => 32,
        Nid::SECP384R1 => 48,
        _ => unreachable!(),
    };

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
    ($name:ident, $alg:expr, $digest:expr) => {
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

macro_rules! define_ecdsa_verifier {
    ($name:ident, $alg:expr, $nid:expr, $digest:expr) => {
        pub struct $name(PKey<Public>);

        impl $name {
            pub(crate) fn new(decoding_key: &DecodingKey) -> Result<Self> {
                if decoding_key.family() != AlgorithmFamily::Ec {
                    return Err(new_error(ErrorKind::InvalidKeyFormat));
                }

                let group = EcGroup::from_curve_name($nid).map_err(Error::from_source)?;
                let (x_bytes, y_bytes) = extract_points(decoding_key.as_bytes(), $nid)?;
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
                let mut verifier =
                    OpenSSLVerifier::new($digest, &self.0).map_err(Error::from_source)?;
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

define_ecdsa_signer!(Es256Signer, Algorithm::ES256, MessageDigest::sha256());
define_ecdsa_verifier!(
    Es256Verifier,
    Algorithm::ES256,
    Nid::X9_62_PRIME256V1,
    MessageDigest::sha256()
);

define_ecdsa_signer!(Es384Signer, Algorithm::ES384, MessageDigest::sha384());
define_ecdsa_verifier!(
    Es384Verifier,
    Algorithm::ES384,
    Nid::SECP384R1,
    MessageDigest::sha384()
);
