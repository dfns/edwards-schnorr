fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    match args.get(1).map(String::as_str) {
        Some("keygen") => {
            let secret_key = ed25519::SigningKey::generate(&mut rand_core::OsRng);

            let secret_key_bytes = secret_key.to_bytes();
            let secret_key_hex = hex::encode(secret_key_bytes);

            eprint!("Secret key: ");
            println!("{secret_key_hex}");
        }

        Some("get-public-key") => {
            let secret_key_hex = args.get(2).expect("missing secret key");
            let secret_key =
                hex::decode(secret_key_hex).expect("malformed secret key hex encoding");
            let secret_key = ed25519::SigningKey::from_bytes(
                &secret_key
                    .try_into()
                    .expect("unexpected size of the secret key"),
            );

            let public_key_bytes = secret_key.verifying_key().to_bytes();
            let public_key_hex = hex::encode(public_key_bytes);

            eprint!("Public key: ");
            println!("{public_key_hex}");
        }

        Some("to-schnorr-key") => {
            let secret_key_hex = args.get(2).expect("missing secret key");
            let secret_key =
                hex::decode(secret_key_hex).expect("malformed secret key hex encoding");
            let secret_key = ed25519::SigningKey::from_bytes(
                &secret_key
                    .try_into()
                    .expect("unexpected size of the secret key"),
            );

            let secret_key = ed25519::hazmat::ExpandedSecretKey::from(&secret_key.to_bytes());
            let secret_scalar = secret_key.scalar.to_bytes();

            eprint!("Schnorr secret key: ");
            println!("{}", hex::encode(secret_scalar));
        }

        Some("sign") => {
            let secret_key_hex = args.get(2).expect("missing secret key");
            let message = args.get(3).expect("missing message");

            let secret_key =
                hex::decode(secret_key_hex).expect("malformed secret key hex encoding");
            let secret_key = ed25519::SigningKey::from_bytes(
                &secret_key
                    .try_into()
                    .expect("unexpected size of the secret key"),
            );

            let sig = ed25519::ed25519::signature::Signer::sign(&secret_key, message.as_bytes());

            eprint!("Signature: ");
            println!("{}", hex::encode(sig.to_bytes()));
        }

        Some("verify") => {
            let public_key = args.get(2).expect("missing public key");
            let message = args.get(3).expect("missing message");
            let sig = args.get(4).expect("missing signature");

            let public_key = hex::decode(public_key).expect("public key: malformed hex encoding");
            let public_key = ed25519::VerifyingKey::from_bytes(
                &public_key.try_into().expect("public key: invalid size"),
            )
            .expect("invalid public key");

            let sig = hex::decode(sig).expect("sig: malformed hex encoding");
            let sig = ed25519::Signature::from_bytes(&sig.try_into().expect("sig: invalid size"));

            public_key
                .verify_strict(message.as_bytes(), &sig)
                .expect("invalid signature");

            println!("Signature is valid!");
        }

        _ => {
            let cmd = &args[0];
            println!(
                "Usage:\n\
                {cmd} keygen — Generate a key, prints secret key to stdout\n\
                {cmd} get-public-key [SECRET_KEY] — Outputs public key for given secret key to stdout\n\
                {cmd} to-schnorr-key [SECRET_KEY] — Converts EdDSA secret key to Schnorr secret key, and outputs it to stdout\n\
                {cmd} sign [SECRET_KEY] [MESSAGE] — Sign a message with provided secret key\n\
                {cmd} verify [PUBLIC_KEY] [MESSAGE] [SIGNATURE] — Verify correctness of the signature"
            );
            std::process::exit(1);
        }
    }
}
