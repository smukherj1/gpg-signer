#!/usr/bin/bash

set -euo pipefail

KEYFLAGS="--pub-key data/test_public_key.pem --priv-key data/test_private_key.pem"
IDENTITY="Test <test@gmail.com>"
GPG_SIGNER="./build/install/gpg-signer/bin/gpg-signer"

echo "Exporting public key..."
$GPG_SIGNER export-public-key $KEYFLAGS --identity "$IDENTITY" --out out/my_public_key.asc

echo "Importing public key..."
gpg --import out/my_public_key.asc

echo "Signing README.md..."
$GPG_SIGNER sign $KEYFLAGS --payload README.md --out out/README.md.asc

echo "Verifying signature..."
gpg --verify out/README.md.asc README.md

echo "Clearsigning data/Release..."
$GPG_SIGNER clearsign $KEYFLAGS --payload data/Release --out out/InRelease

echo "Verifying clear signature..."
gpg --verify out/InRelease



