package dev.flanker.newhope.chiper;

import dev.flanker.newhope.api.PublicKey;

public final class NewHopePublicKey implements PublicKey {
    private final int[] b;
    private final byte[] publicSeed;

    public NewHopePublicKey(int[] b, byte[] publicSeed) {
        this.b = b;
        this.publicSeed = publicSeed;
    }

    @Override
    public int[] b() {
        return b;
    }

    @Override
    public byte[] publicSeed() {
        return publicSeed;
    }
}
