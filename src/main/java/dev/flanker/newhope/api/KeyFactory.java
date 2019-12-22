package dev.flanker.newhope.api;

public interface KeyFactory {
    PublicKey decodePublicKey(byte[] encoded);

    PrivateKey decodePrivateKey(byte[] encoded);

    byte[] encodePrivateKey(PrivateKey privateKey);

    byte[] encodePublicKey(PublicKey publicKey);
}
