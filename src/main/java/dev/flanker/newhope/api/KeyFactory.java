package dev.flanker.newhope.api;

public interface KeyFactory {
    PublicKey publicKey(byte[] encoded);

    PrivateKey privateKey(byte[] encoded);
}
