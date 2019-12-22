package dev.flanker.newhope.internal.domain;

public class DecodedCiphertext {
    private final int[] poly;
    private final byte[] h;

    public DecodedCiphertext(int[] poly, byte[] h) {
        this.poly = poly;
        this.h = h;
    }

    public int[] getPoly() {
        return poly;
    }

    public byte[] getH() {
        return h;
    }
}
