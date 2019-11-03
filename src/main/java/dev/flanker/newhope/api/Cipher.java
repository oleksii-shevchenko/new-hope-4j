package dev.flanker.newhope.api;

public interface Cipher {
    KeyPair generateKeyPair();

    byte[] encrypt(byte[] message, PublicKey key);

    byte[] decrypt(byte[] ciphertext, PrivateKey key);
}
