use std::{fmt::Display, fs};

use botan::Privkey;
use clap::ValueEnum;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};
use strum::EnumIter;

pub static ALGORITHMS: [&str; 12] = [
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
    "ES384", "EdDSA",
];

#[derive(Clone, ValueEnum, EnumIter, Serialize, Deserialize)]
pub enum Provider {
    #[serde(rename = "aws-lc-rs")]
    #[clap(name = "aws-lc-rs")]
    AwsLcRs,
    #[serde(rename = "rust-crypto")]
    #[clap(name = "rust-crypto")]
    RustCrypto,
    #[serde(rename = "openssl")]
    #[clap(name = "openssl")]
    OpenSSL,
    #[serde(rename = "botan")]
    #[clap(name = "botan")]
    Botan,
}

impl Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Provider::AwsLcRs => write!(f, "aws-lc-rs"),
            Provider::RustCrypto => write!(f, "rust-crypto"),
            Provider::OpenSSL => write!(f, "openssl"),
            Provider::Botan => write!(f, "botan"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
}

pub fn keypair_from_file(name: &str) -> (EncodingKey, DecodingKey) {
    let key = fs::read_to_string(key_path(name)).unwrap();
    if name == "hmac" {
        return (
            EncodingKey::from_base64_secret(&key).unwrap(),
            DecodingKey::from_base64_secret(&key).unwrap(),
        );
    }

    let privkey = Privkey::load_pem(&key).unwrap();
    let pubkey_pem = privkey.pubkey().unwrap().pem_encode().unwrap();
    let privkey_pem = privkey.pem_encode().unwrap();
    let pubkey = pubkey_pem.as_bytes();
    let privkey = privkey_pem.as_bytes();

    match name {
        "rsa" => (
            EncodingKey::from_rsa_pem(privkey).unwrap(),
            DecodingKey::from_rsa_pem(pubkey).unwrap(),
        ),
        "eddsa" => (
            EncodingKey::from_ed_pem(privkey).unwrap(),
            DecodingKey::from_ed_pem(pubkey).unwrap(),
        ),
        "ecdsa_secp256r1" | "ecdsa_secp384r1" => (
            EncodingKey::from_ec_pem(privkey).unwrap(),
            DecodingKey::from_ec_pem(pubkey).unwrap(),
        ),
        _ => unreachable!(),
    }
}

pub fn install_from_provider(provider: &Provider) {
    match provider {
        Provider::AwsLcRs => {
            jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER
                .install_default()
                .unwrap();
        }
        Provider::RustCrypto => {
            jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER
                .install_default()
                .unwrap();
        }
        Provider::OpenSSL => {
            jsonwebtoken_openssl::install_default().unwrap();
        }
        Provider::Botan => {
            jsonwebtoken_botan::install_default().unwrap();
        }
    }
}

pub fn key_path(name: &str) -> String {
    fs::create_dir_all("data/keys").unwrap();
    if name == "hmac" {
        "data/keys/hmac.key".to_string()
    } else {
        format!("data/keys/{}.pem", name)
    }
}

pub fn token_path(provider: &Provider, algorithm: &str) -> String {
    fs::create_dir_all(format!("data/providers/{}", provider)).unwrap();
    format!("data/providers/{}/{}.jwt", provider, algorithm)
}
