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
