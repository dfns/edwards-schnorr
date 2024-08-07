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

> Examples below use third-party libraries which should be used at your own risk.

### Golang
This example uses `kyber` library which implements Schnorr generic over choice of curve. We
simply use Schnorr signing with `ed25519` suite, which results into EdDSA-compatible
signatures.

```go
package main

import "flag"
import "encoding/hex"
import "os"

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

	println(hex.EncodeToString(sig))
}
```
