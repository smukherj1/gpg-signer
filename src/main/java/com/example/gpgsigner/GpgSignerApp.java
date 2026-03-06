package com.example.gpgsigner;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.util.concurrent.Callable;

@Command(name = "gpg-signer", mixinStandardHelpOptions = true, version = "1.0", description = "A CLI tool to generate PGP keys and signatures utilizing raw RSA keys or Cloud KMS.", subcommands = {
        GpgSignerApp.ExportPublicKeyCommand.class,
        GpgSignerApp.SignCommand.class
})
public class GpgSignerApp implements Callable<Integer> {

    public static void main(String[] args) {
        int exitCode = new CommandLine(new GpgSignerApp()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() {
        CommandLine.usage(this, System.out);
        return 0;
    }

    @Command(name = "export-public-key", description = "Exports an RSA public key as a PGP public key")
    static class ExportPublicKeyCommand implements Callable<Integer> {
        @Option(names = "--pub-key", required = true, description = "Path to the RSA public key PEM file")
        File pubKey;

        @Option(names = "--priv-key", required = true, description = "Path to the RSA private key PEM file (to self-sign the identity)")
        File privKey;

        @Option(names = "--identity", required = true, description = "The User ID identity for the PGP key (e.g., 'Test <test@example.com>')")
        String identity;

        @Option(names = "--out", required = true, description = "Path to the output PGP public key file (.asc)")
        File out;

        @Override
        public Integer call() {
            try {
                PgpSignerService.exportPublicKey(pubKey, privKey, identity, out);
                System.out.println("Successfully exported PGP public key to: " + out.getAbsolutePath());
                return 0;
            } catch (Exception e) {
                e.printStackTrace();
                return 1;
            }
        }
    }

    @Command(name = "sign", description = "Generates a detached PGP signature for a payload")
    static class SignCommand implements Callable<Integer> {
        @Option(names = "--priv-key", required = true, description = "Path to the RSA private key PEM file")
        File privKey;

        @Option(names = "--payload", required = true, description = "Path to the file to sign")
        File payload;

        @Option(names = "--out", required = true, description = "Path to the output PGP signature file (.asc)")
        File out;

        @Override
        public Integer call() {
            try {
                PgpSignerService.signPayload(privKey, payload, out);
                System.out.println("Successfully generated PGP signature to: " + out.getAbsolutePath());
                return 0;
            } catch (Exception e) {
                e.printStackTrace();
                return 1;
            }
        }
    }
}
