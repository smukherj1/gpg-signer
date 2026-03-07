#!/usr/bin/bash

set -euo pipefail

KEYFLAGS="--pub-key data/test_public_key.pem --priv-key data/test_private_key.pem"
IDENTITY="Test <test@gmail.com>"

echo "Exporting public key..."
./build/install/gpg-signer/bin/gpg-signer export-public-key $KEYFLAGS --identity "$IDENTITY" --out my_public_key.asc

echo "Importing public key..."
gpg --import my_public_key.asc

echo "Signing README.md..."
./build/install/gpg-signer/bin/gpg-signer sign $KEYFLAGS --payload README.md --out README.md.asc

echo "Verifying signature..."
gpg --verify README.md.asc README.md

echo "Cleaning up..."
rm my_public_key.asc README.md.asc



