package com.example.gpgsigner;

import org.bouncycastle.openpgp.operator.PGPContentSigner;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;

public class KmsContentSigner implements PGPContentSigner {

    private final PrivateKey privateKey;
    private final int keyAlgorithm;
    private final int hashAlgorithm;
    private final ByteArrayOutputStream buffer;
    private final MessageDigest md;

    private final int signatureType;
    private final long keyId;

    public KmsContentSigner(PrivateKey privateKey, int keyAlgorithm, int hashAlgorithm, int signatureType, long keyId)
            throws Exception {
        this.privateKey = privateKey;
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
        this.signatureType = signatureType;
        this.keyId = keyId;
        this.buffer = new ByteArrayOutputStream();

        // Setup a concurrent digest for Bouncy Castle if it calls getDigest().
        // For HashAlgorithmTags.SHA256 (ID: 8)
        this.md = MessageDigest.getInstance("SHA-256");
    }

    @Override
    public int getHashAlgorithm() {
        return hashAlgorithm;
    }

    @Override
    public int getKeyAlgorithm() {
        return keyAlgorithm;
    }

    @Override
    public int getType() {
        return signatureType;
    }

    @Override
    public long getKeyID() {
        return keyId;
    }

    @Override
    public OutputStream getOutputStream() {
        return new OutputStream() {
            @Override
            public void write(int b) {
                buffer.write(b);
                md.update((byte) b);
            }

            @Override
            public void write(byte[] b, int off, int len) {
                buffer.write(b, off, len);
                md.update(b, off, len);
            }
        };
    }

    @Override
    public byte[] getSignature() {
        try {
            // NOTE FOR FUTURE: This is where we integrate with Google Cloud KMS.
            // When delegating to KMS, instead of this JVM Signature instance, we would:
            // return cloudKmsClient.asymmetricSign(keyName, Digest.newBuilder()
            // .setSha256(ByteString.copyFrom(md.digest())).build())
            // .getSignature().toByteArray();

            // For now, simulate the remote signing operation using the local PrivateKey
            // object:
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(buffer.toByteArray());
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate signature via KmsContentSigner", e);
        }
    }

    @Override
    public byte[] getDigest() {
        return md.digest();
    }
}
