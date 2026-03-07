package com.example.gpgsigner;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Files;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class PgpSignerServiceTest {

    @Test
    public void testExportPublicKeyAndSign() throws Exception {
        File privKey = new File("data/test_private_key.pem");
        File pubKey = new File("data/test_public_key.pem");

        if (!privKey.exists() || !pubKey.exists()) {
            System.out.println("Test keys not found, skipping...");
            return;
        }

        File outPub = File.createTempFile("pub", ".asc");
        File outSig = File.createTempFile("sig", ".asc");
        File payload = File.createTempFile("payload", ".txt");

        Files.writeString(payload.toPath(), "Hello World");

        KmsContentSigner signer = new KmsContentSigner(pubKey, privKey, PublicKeyAlgorithmTags.RSA_GENERAL,
                HashAlgorithmTags.SHA256);
        PgpSignerService service = new PgpSignerService(signer);

        service.exportPublicKey("Test User <test@example.com>", outPub);
        assertTrue(outPub.length() > 0);

        service.signPayload(payload, outSig);
        assertTrue(outSig.length() > 0);

        outPub.deleteOnExit();
        outSig.deleteOnExit();
        payload.deleteOnExit();
    }
}
