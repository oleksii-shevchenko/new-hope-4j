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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NewHopePublicKey that = (NewHopePublicKey) o;
        return Arrays.equals(b, that.b) &&
                Arrays.equals(publicSeed, that.publicSeed);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(b);
        result = 31 * result + Arrays.hashCode(publicSeed);
        return result;
    }
}
