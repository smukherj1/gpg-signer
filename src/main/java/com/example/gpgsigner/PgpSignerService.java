package com.example.gpgsigner;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;

import java.io.*;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

public class PgpSignerService {

    private static final String VERSION = "GPG Signer 1.0";
    private static final Date PUBLIC_KEY_CREATION_DATE = Date.from(LocalDate.of(2026, 1, 1)
            .atStartOfDay(ZoneId.systemDefault()).toInstant());

    private final KmsContentSigner signer;

    public PgpSignerService(KmsContentSigner signer) {
        this.signer = signer;
    }

    public void exportPublicKey(java.lang.String identity, File outputFile)
            throws Exception {
        RSAPublicKey rsaPub = signer.getPublicKey();

        JcaPGPKeyConverter pgpConverter = new JcaPGPKeyConverter().setProvider("BC");
        PGPPublicKey pgpPub = pgpConverter.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, rsaPub,
                PUBLIC_KEY_CREATION_DATE);

        PGPPrivateKey dummyPgpPriv = new PGPPrivateKey(pgpPub.getKeyID(), pgpPub.getPublicKeyPacket(), null);

        PGPSignatureGenerator sGen = new PGPSignatureGenerator(signer);
        sGen.init(PGPSignature.POSITIVE_CERTIFICATION, dummyPgpPriv);

        PGPPublicKey signedKey = PGPPublicKey.addCertification(pgpPub, identity,
                sGen.generateCertification(identity, pgpPub));

        ArmoredOutputStream.Builder outputBuilder = ArmoredOutputStream.builder().setVersion(VERSION);

        try (ArmoredOutputStream aos = outputBuilder.build(new FileOutputStream(outputFile))) {
            signedKey.encode(aos);
        }
    }

    public void signPayload(File payloadFile, File outputFile) throws Exception {
        RSAPublicKey rsaPub = signer.getPublicKey();

        JcaPGPKeyConverter pgpConverter = new JcaPGPKeyConverter().setProvider("BC");
        PGPPublicKey pgpPub = pgpConverter.getPGPPublicKey(PublicKeyAlgorithmTags.RSA_GENERAL, rsaPub,
                PUBLIC_KEY_CREATION_DATE);

        PGPPrivateKey dummyPgpPriv = new PGPPrivateKey(pgpPub.getKeyID(), pgpPub.getPublicKeyPacket(), null);

        PGPSignatureGenerator sGen = new PGPSignatureGenerator(signer);
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
}
