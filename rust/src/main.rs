fn main() {
    // Usage: ./sign SECRET_KEY MESSAGE
    let args = std::env::args().collect::<Vec<_>>();
    let [_, secret_key_hex, message] = args.try_into().expect("expected two args");

    // Parse secret key as `curve25519_dalek::Scalar`
    let secret_key = hex::decode(secret_key_hex).expect("secret key: malformed hex");
    let secret_key = secret_key
        .try_into()
        .expect("secret key must be 32 bytes long");
    let secret_key = curve25519_dalek::Scalar::from_bytes_mod_order(secret_key);

    // Construct expanded secret key (which is not how library is supposed to be used...)
    let expanded_secret_key = ed25519_dalek::hazmat::ExpandedSecretKey {
        scalar: secret_key,
        // Sample `hash_prefix` from a cryptographically secure randomness source.
        // `rand::random()` uses `ThreadRng` which is secure.
        hash_prefix: rand::random(),
    };

    // Sign a message using `hazmat::raw_sign`. For this call to be secure, we need that:
    // 1) Public key **must be** derived from the expanded secret key (the 3rd arg)
    // 2) hash_prefix must be sampled from cryptographically-secure randomness source
    let sig = ed25519_dalek::hazmat::raw_sign::<ed25519_dalek::Sha512>(
        &expanded_secret_key,
        message.as_bytes(),
        &(&expanded_secret_key).into(),
    );
    let sig_hex = hex::encode(sig.to_bytes());
    eprint!("Signature: ");
    println!("{sig_hex}");
}
