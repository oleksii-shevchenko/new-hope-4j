package dev.flanker.newhope.chiper.domain;

import dev.flanker.newhope.api.PublicKey;

import java.util.Arrays;

public class NewHopePublicKey implements PublicKey {
    private final int[] b;
    private final byte[] publicSeed;

    public NewHopePublicKey(int[] b, byte[] publicSeed) {
        this.b = Arrays.copyOf(b, b.length);
        this.publicSeed = Arrays.copyOf(publicSeed, publicSeed.length);
    }

    public int[] b() {
        return b;
    }

    public byte[] publicSeed() {
        return publicSeed;
    }
}
