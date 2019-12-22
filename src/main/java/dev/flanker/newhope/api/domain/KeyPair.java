package dev.flanker.newhope.api.domain;

import java.util.Arrays;

public class KeyPair {
    private final byte[] privateKey;
    private final byte[] publicKey;

    public KeyPair(byte[] privateKey, byte[] publicKey) {
        this.privateKey = Arrays.copyOf(privateKey, privateKey.length);
        this.publicKey = Arrays.copyOf(publicKey, publicKey.length);
    }

    public byte[] getPrivateKey() {
        return Arrays.copyOf(privateKey, privateKey.length);
    }

    public byte[] getPublicKey() {
        return Arrays.copyOf(publicKey, publicKey.length);
    }
}
