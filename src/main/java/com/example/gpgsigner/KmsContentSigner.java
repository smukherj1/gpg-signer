package com.example.gpgsigner;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.operator.PGPContentSigner;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.*;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KmsContentSigner implements PGPContentSignerBuilder {

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final int keyAlgorithm;
    private final int hashAlgorithm;

    public KmsContentSigner(File pubKeyFile, File privKeyFile, int keyAlgorithm, int hashAlgorithm) throws Exception {
        this.publicKey = readPublicKey(pubKeyFile);
        this.privateKey = readPrivateKey(privKeyFile);
        this.keyAlgorithm = keyAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public PGPContentSigner build(final int signatureType, PGPPrivateKey pgpPrivKey) throws PGPException {
        return new InternalContentSigner(signatureType, pgpPrivKey.getKeyID());
    }

    private static RSAPrivateKey readPrivateKey(File f) throws Exception {
        try (FileReader fr = new FileReader(f);
                PEMParser pemParser = new PEMParser(fr)) {
            Object o = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (o instanceof PEMKeyPair) {
                return (RSAPrivateKey) converter.getKeyPair((PEMKeyPair) o).getPrivate();
            } else if (o instanceof PrivateKeyInfo) {
                return (RSAPrivateKey) converter.getPrivateKey((PrivateKeyInfo) o);
            }
            throw new IllegalArgumentException(
                    "Unknown private key format: " + (o != null ? o.getClass().getName() : "null"));
        }
    }

    private static RSAPublicKey readPublicKey(File f) throws Exception {
        try (FileReader fr = new FileReader(f);
                PEMParser pemParser = new PEMParser(fr)) {
            Object o = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
            if (o instanceof SubjectPublicKeyInfo) {
                return (RSAPublicKey) converter.getPublicKey((SubjectPublicKeyInfo) o);
            }
            throw new IllegalArgumentException(
                    "Unknown public key format: " + (o != null ? o.getClass().getName() : "null"));
        }
    }

    private class InternalContentSigner implements PGPContentSigner {
        private final int signatureType;
        private final long keyId;
        private final ByteArrayOutputStream buffer;
        private final MessageDigest md;

        InternalContentSigner(int signatureType, long keyId) {
            this.signatureType = signatureType;
            this.keyId = keyId;
            this.buffer = new ByteArrayOutputStream();
            try {
                this.md = MessageDigest.getInstance("SHA-256");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
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
}
