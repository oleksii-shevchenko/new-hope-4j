package dev.flanker.newhope.api;

import dev.flanker.newhope.api.domain.KeyPair;

public interface Cipher {
    void dualMode(KeyPair pair);

    void encryptionMode(byte[] publicKey);

    void encryptionMode(PublicKey publicKey);

    void decryptionMode(byte[] privateKey);

    void decryptionMode(PrivateKey privateKey);

    KeyPair generateKeyPair();

    byte[] encrypt(byte[] message);

    byte[] decrypt(byte[] ciphertext);

    KeyFactory getKeyFactory();
}
