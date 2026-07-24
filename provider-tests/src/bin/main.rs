use std::{fs, str::FromStr};

use botan::{Privkey, RandomNumberGenerator};
use clap::Parser;
use jsonwebtoken::{Algorithm, Header, encode};
use provider_tests::{
    ALGORITHMS, Claims, Provider, install_from_provider, key_path, keypair_from_file, token_path,
};

#[derive(Parser)]
struct Args {
    #[arg(short, long, value_enum, required_unless_present = "keys")]
    provider: Option<Provider>,
    #[arg(short, long)]
    keys: bool,
}

/// cargo run -- -p <rust-crypto | aws-lc-rs | botan | openssl>
/// The only reason this is not generated at test run time is that it's impossible to uninstall
/// a `CryptoProvider`, and we'd need to somehow install all of them in sequence
fn main() {
    let args = Args::parse();

    if args.keys {
        install_from_provider(&Provider::Botan);
        generate_keys();
        return;
    }

    let provider = args.provider.unwrap();

    install_from_provider(&provider);
    generate_tokens(provider);
}

fn generate_keys() {
    let mut rng = RandomNumberGenerator::new().unwrap();
    let hmac = rng.read(32).unwrap();
    let rsa = Privkey::create("RSA", "4096", &mut rng).unwrap();
    let ecdsa_secp256r1 = Privkey::create("ECDSA", "secp256r1", &mut rng).unwrap();
    let ecdsa_secp384r1 = Privkey::create("ECDSA", "secp384r1", &mut rng).unwrap();
    let eddsa = Privkey::create("Ed25519", "", &mut rng).unwrap();

    fs::write(key_path("hmac"), botan::base64_encode(&hmac).unwrap()).unwrap();

    for (name, key) in [
        ("rsa", rsa),
        ("ecdsa_secp256r1", ecdsa_secp256r1),
        ("ecdsa_secp384r1", ecdsa_secp384r1),
        ("eddsa", eddsa),
    ] {
        fs::write(key_path(name), key.pem_encode().unwrap()).unwrap();
    }
}

fn generate_tokens(provider: Provider) {
    let hmac_key = keypair_from_file("hmac").0;
    let rsa_key = keypair_from_file("rsa").0;
    let ecdsa_key_256 = keypair_from_file("ecdsa_secp256r1").0;
    let ecdsa_key_384 = keypair_from_file("ecdsa_secp384r1").0;
    let eddsa_key = keypair_from_file("eddsa").0;

    for algorithm in ALGORITHMS {
        let token_path = token_path(&provider, algorithm);
        if fs::exists(&token_path).unwrap() {
            println!("Token for {} exists, skipping", algorithm);
            continue;
        }
        println!("Generating token for {}", algorithm);
        let algo = Algorithm::from_str(algorithm).unwrap();
        let encoding_key = match algo {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => &hmac_key,
            Algorithm::ES256 => &ecdsa_key_256,
            Algorithm::ES384 => &ecdsa_key_384,
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => &rsa_key,
            Algorithm::EdDSA => &eddsa_key,
            _ => {
                println!("No key generation defined for {algo:?}");
                continue;
            }
        };

        let claims = Claims {
            sub: "provider-tests".to_string(),
            exp: u64::MAX,
        };

        let token = encode(&Header::new(algo), &claims, encoding_key).unwrap();
        fs::write(token_path, token).unwrap();
    }
}
