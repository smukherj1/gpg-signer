package com.example.gpgsigner;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.*;
import java.math.BigInteger;
import java.security.Security;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

public class PgpSignerService {

    private static final String VERSION = "GPG Signer 1.0";
    private static final Date PUBLIC_KEY_CREATION_DATE = Date.from(LocalDate.of(2026, 1, 1)
            .atStartOfDay(ZoneId.systemDefault()).toInstant());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void exportPublicKey(File rsaPubFile, File rsaPrivFile, String identity, File outputFile)
            throws Exception {
        RSAPublicKey rsaPub = readPublicKey(rsaPubFile);
        RSAPrivateKey rsaPriv = readPrivateKey(rsaPrivFile);

        JcaPGPKeyConverter pgpConverter = new JcaPGPKeyConverter().setProvider("BC");
        PGPPublicKey pgpPub = pgpConverter.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, rsaPub,
                PUBLIC_KEY_CREATION_DATE);

        PGPPrivateKey dummyPgpPriv = new PGPPrivateKey(pgpPub.getKeyID(), pgpPub.getPublicKeyPacket(), null);

        KmsContentSignerBuilder signerBuilder = new KmsContentSignerBuilder(rsaPriv, PublicKeyAlgorithmTags.RSA_GENERAL,
                HashAlgorithmTags.SHA256);
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(signerBuilder);
        sGen.init(PGPSignature.POSITIVE_CERTIFICATION, dummyPgpPriv);

        PGPPublicKey signedKey = PGPPublicKey.addCertification(pgpPub, identity,
                sGen.generateCertification(identity, pgpPub));

        ArmoredOutputStream.Builder outputBuilder = ArmoredOutputStream.builder().setVersion(VERSION);

        try (ArmoredOutputStream aos = outputBuilder.build(new FileOutputStream(outputFile))) {
            signedKey.encode(aos);
        }
    }

    public static void signPayload(File privFile, File payloadFile, File outputFile) throws Exception {
        RSAPrivateKey rsaPriv = readPrivateKey(privFile);

        BigInteger pubExp = BigInteger.valueOf(65537);
        if (rsaPriv instanceof RSAPrivateCrtKey) {
            pubExp = ((RSAPrivateCrtKey) rsaPriv).getPublicExponent();
        }
        java.security.spec.RSAPublicKeySpec pubSpec = new java.security.spec.RSAPublicKeySpec(rsaPriv.getModulus(),
                pubExp);
        RSAPublicKey rsaPub = (RSAPublicKey) java.security.KeyFactory.getInstance("RSA").generatePublic(pubSpec);

        JcaPGPKeyConverter pgpConverter = new JcaPGPKeyConverter().setProvider("BC");
        PGPPublicKey pgpPub = pgpConverter.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, rsaPub,
                PUBLIC_KEY_CREATION_DATE);

        PGPPrivateKey dummyPgpPriv = new PGPPrivateKey(pgpPub.getKeyID(), pgpPub.getPublicKeyPacket(), null);

        KmsContentSignerBuilder signerBuilder = new KmsContentSignerBuilder(rsaPriv, PublicKeyAlgorithmTags.RSA_GENERAL,
                HashAlgorithmTags.SHA256);
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(signerBuilder);
        sGen.init(PGPSignature.BINARY_DOCUMENT, dummyPgpPriv);

        ArmoredOutputStream.Builder outputBuilder = ArmoredOutputStream.builder().setVersion(VERSION);

        try (InputStream in = new FileInputStream(payloadFile);
                ArmoredOutputStream aos = outputBuilder.build(new FileOutputStream(outputFile))) {

            BCPGOutputStream bOut = new BCPGOutputStream(aos);

            byte[] buf = new byte[8192];
            int len;
            while ((len = in.read(buf)) >= 0) {
                sGen.update(buf, 0, len);
            }

            sGen.generate().encode(bOut);
        }
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
}
