#!/usr/bin/bash

# Generate a private key
openssl genrsa -out data/test_private_key.pem 2048

# Generate a public key
openssl rsa -in data/test_private_key.pem -pubout -out data/test_public_key.pem

# Generate a self signed certificate
openssl req -new -x509 -key data/test_private_key.pem -out data/test_certificate.pem -days 365 -subj "/CN=Test"

I'd like a binary that can:
- Generate PGP signatures that'll verify with the gpg tool using the RSA private signing key in @beautifulMention. This is just a test signing private key. My real intention is to use a remote signing key on a cloud service like Google Cloud KMS that will be given a payload and can return the signed payload.

- Export the RSA signing public key in @beautifulMention as a PGP public key. The tool should accept the path to the public key and the PGP identity represented by the public key and generate a public key in the PGP format, i.e., something that can be exported to a gpg keyserver or can be used with gpg to verify signatures.

I imagine java will be a good language to implement this because the Bouncy Castle library has good support for PGP.