<!-- 
  DO NOT EDIT THIS FILE!
  This file was generated automatically via a script. Please,
  edit `README-tpl.md` instead.
-->

# Schnorr on Edwards curve: producing EdDSA-compatible signatures

<!-- toc -->

- [Why?](#why)
- [Solution Overview](#solution-overview)
- [Examples in different languages](#examples-in-different-languages)
  * [Golang](#golang)
  * [Rust](#rust)

<!-- tocstop -->

## Why?

When you export an EdDSA key from Dfns, what you get is actually a Schnorr key. The reason
for it is that Dfns uses Threshold Signing Schemes to perform signing, and it's practically
impossible to thresholdize EdDSA, however, it's extremely easy to thresholdize Schnorr
(which is as secure as EdDSA) in a such way that it produces EdDSA-compatible signatures.

In this article, we'll describe how you can use Schnorr key in order to produce EdDSA-compatible
signatures, so you can continue to use your key after you left Dfns platform.

Note that it only concerns EdDSA key. Other types of keys do not require any special way of
working with them after key export (for instance, if you exported an ECDSA key, you can use
it as a regular ECDSA key).

## Solution Overview
Generally speaking, in order to produce EdDSA-compatible signatures using Schnorr key, you
need to find a library or a tool that supports performing Schnorr signing on Edwards curve
(a.k.a. ed25519 and curve25519). Most likely, what you need is a library that implements
a Schnorr signing generic over choice of curve, and then plug-in Edwards curve.

From security perspective, it's perfectly fine to do that as long as the software is properly
implemented and you're using a cryptographically secure source of randomness.

## Examples in different languages
Below you can find examples of doing Schnorr signing that produces EdDSA-compatible signatures.
Complete project per each example can be found in the repo.

> [!WARNING]
> Examples below use third-party libraries. Dfns didn't develop nor audit them. Examples exclusively
> serve demonstration purpose to show how signing could be implemented. Use them at your own risk.

### Golang
This example uses `kyber` library which implements Schnorr generic over choice of curve. We
simply use Schnorr signing with `ed25519` suite, which results into EdDSA-compatible
signatures.

Complete project can be found in [`./go`](./go)

```go
package main

import "flag"
import "encoding/hex"
import "os"
import "fmt"

import "github.com/dedis/kyber/sign/schnorr"
import "github.com/dedis/kyber/suites"

func main() {
	message := flag.String("message", "", "Message to sign")
	secretScalarHex := flag.String("secret-key", "", "Schnorr secret key, in hex")
	flag.Parse()

	if *message == "" || *secretScalarHex == "" {
		usage := "Usage:\n" +
			"./sign -secret-scalar SK -message MSG --- Sign a message\n"
		println(usage)
		os.Exit(1)
	}

	edwardsSuite := suites.MustFind("ed25519")

	secretScalarBytes, err := hex.DecodeString(*secretScalarHex)
	if err != nil {
		panic("secret scalar: malformed hex encoding: " + err.Error())
	}

	secretScalar := edwardsSuite.Scalar()
	secretScalar.UnmarshalBinary(secretScalarBytes)

	sig, err := schnorr.Sign(edwardsSuite, secretScalar, []byte(*message))
	if err != nil {
		panic("signing error: " + err.Error())
	}

	fmt.Println(hex.EncodeToString(sig))
}
```

### Rust
In Rust, we can use `ed25519-dalek` crate that provides EdDSA signing but also allows
signing from Schnorr key. However, note that this requires using low-level `hazmat`
library API which is discouraged to use.

Complete project can be found in [`./rust`](./rust)

```rust
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
```
