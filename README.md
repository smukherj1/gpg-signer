# GPG Signer

A Java binary that can generate PGP signatures and export PGP public keys using raw RSA keys. This project is specifically designed with the intention of delegating the signing operations to a remote service like Google Cloud KMS.

## Technical Design

The core of the key generation and signing process is implemented using the **Bouncy Castle (BC)** library, specifically the `bcprov`, `bcpg`, and `bcpkix` packages. 

### Key Storage Abstraction
To abstract away the location of the private key, the project utilizes the `KmsContentSigner` class, which implements the Bouncy Castle `PGPContentSignerBuilder` interface. 

`KmsContentSigner` is responsible for:
1. Loading the raw RSA public and private keys from PEM files.
2. Providing access to the `RSAPublicKey` while keeping the `RSAPrivateKey` encapsulated.
3. Building a `PGPContentSigner` that performs the actual signing operations.

By injecting `KmsContentSigner` into services like `PgpSignerService`, the system remains decoupled from the specific key storage mechanism. To integrate with Cloud KMS later, one simply needs to update `KmsContentSigner` to delegate signing calls to the Cloud KMS SDK instead of using the local private key.

### Deterministic Key Creation
In OpenPGP, a Signature packet identifies the signing key using an Issuer Key ID, which is derived from the public key's properties and creation timestamp. To ensure consistency between exported public keys and generated signatures, `PgpSignerService` uses a deterministic key creation date (January 1, 2026).

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

Run `test.sh`