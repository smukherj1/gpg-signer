#!/usr/bin/bash

set -euo pipefail

KEYFLAGS="--pub-key data/test_public_key.pem --priv-key data/test_private_key.pem"
IDENTITY="Test <test@gmail.com>"
GPG_SIGNER="./build/install/gpg-signer/bin/gpg-signer"

echo "Exporting public key..."
$GPG_SIGNER export-public-key $KEYFLAGS --identity "$IDENTITY" --out out/my_public_key.asc

echo "Importing public key..."
gpg --import out/my_public_key.asc

# Test Case 1: Detached Signature.
echo "Signing README.md..."
$GPG_SIGNER sign $KEYFLAGS --payload README.md --out out/README.md.asc

echo "Verifying signature..."
gpg --verify out/README.md.asc README.md


# Test Case 2: Clear Signature.
echo "Clearsigning data/Release..."
$GPG_SIGNER clearsign $KEYFLAGS --payload data/Release --out out/InRelease

echo "Verifying clear signature..."
gpg --verify out/InRelease

# Test Case 3: Clear Signature with special characters.
echo "Clearsigning data/ClearSign.txt..."
$GPG_SIGNER clearsign $KEYFLAGS --payload data/ClearSign.txt --out out/ClearSign.txt.asc

echo "Verifying clear signature..."
gpg --verify out/ClearSign.txt.asc
