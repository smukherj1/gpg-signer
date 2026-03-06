package com.example.gpgsigner;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;

import java.security.PrivateKey;

public class KmsContentSignerBuilder implements PGPContentSignerBuilder {
    private final PrivateKey privateKey;
    private final int keyAlgorithm;
    private final int hashAlgorithm;

    public KmsContentSignerBuilder(PrivateKey privateKey, int keyAlgorithm, int hashAlgorithm) {
        this.privateKey = privateKey;
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    @Override
    public PGPContentSigner build(final int signatureType, org.bouncycastle.openpgp.PGPPrivateKey privateKey)
            throws PGPException {
        try {
            return new KmsContentSigner(this.privateKey, keyAlgorithm, hashAlgorithm, signatureType,
                    privateKey.getKeyID());
        } catch (Exception e) {
            throw new PGPException("Failed to build KMS content signer", e);
        }
    }
}
