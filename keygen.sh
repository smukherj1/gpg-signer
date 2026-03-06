#!/usr/bin/bash

# Generate a private key
openssl genrsa -out data/test_private_key.pem 2048

# Generate a public key
openssl rsa -in data/test_private_key.pem -pubout -out data/test_public_key.pem

# Generate a self signed certificate
openssl req -new -x509 -key data/test_private_key.pem -out data/test_certificate.pem -days 365 -subj "/CN=Test"
