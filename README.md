# GPG Signer

A Java binary that can generate PGP signatures and export PGP public keys using raw RSA keys. This project is specifically designed with the intention of delegating the signing operations to a remote service like Google Cloud KMS.

## Technical Design

The core of the key generation and signing process is implemented using the **Bouncy Castle (BC)** library, specifically the `bcprov`, `bcpg`, and `bcpkix` packages. 

### PGPContentSigner Abstraction
Bouncy Castle's OpenPGP API interacts with private keys through the `PGPContentSigner` interface. To abstract away the location of the private key (i.e., whether it's local or residing in Cloud KMS), the project implements a custom `KmsContentSigner`. 

When generating a signature, Bouncy Castle writes the data-to-be-signed to the `OutputStream` provided by `KmsContentSigner`. Once all data is digested, it calls `getSignature()`. Currently, this method fulfills the signature using a local Java `java.security.PrivateKey`. To integrate with Cloud KMS later, one simply needs to replace this local signing call with the appropriate Cloud KMS API SDK call.

### Deterministic Key Creation
In OpenPGP, a Signature packet identifies the signing key using an Issuer Key ID. This ID is derived from the properties of the Public Key at the moment of its creation (including the creation timestamp). 

To ensure that the signature's Issuer Key ID matches the exported public key perfectly, `PgpSignerService` utilizes a hardcoded, deterministic key creation date (January 1, 2024) across both the public key export command and the signature generation command.

## How to Build

The project uses Gradle for its build system. A helper script is provided to automatically download a standalone Gradle distribution if you don't have it installed globally.

```bash
# Downloads Gradle to .gradle-bin/ and builds the CLI distribution
./run-build.sh
```

Upon success, an executable script will be available at `./build/install/gpg-signer/bin/gpg-signer`.

## How to Test

### Running the automated tests
The project uses JUnit 5 to programmatically verify public key exports and signature generation.

```bash
./.gradle-bin/gradle-9.4.0/bin/gradle test
```

### Manual Verification using GnuPG

1. **Export the raw RSA key as a PGP Public Key**
   ```bash
   ./build/install/gpg-signer/bin/gpg-signer export-public-key \
     --pub-key data/test_public_key.pem \
     --priv-key data/test_private_key.pem \
     --identity "Test User <test@example.com>" \
     --out my_public_key.asc
   ```

2. **Import the key to your GnuPG keyring**
   ```bash
   gpg --import my_public_key.asc
   ```

3. **Sign a payload**
   ```bash
   ./build/install/gpg-signer/bin/gpg-signer sign \
     --priv-key data/test_private_key.pem \
     --payload README.md \
     --out my_signature.asc
   ```

4. **Verify the signature against the payload**
   ```bash
   gpg --verify my_signature.asc README.md
   ```