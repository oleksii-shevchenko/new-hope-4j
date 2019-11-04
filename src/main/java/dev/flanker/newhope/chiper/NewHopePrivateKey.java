package dev.flanker.newhope.chiper;

import dev.flanker.newhope.api.PrivateKey;

public final class NewHopePrivateKey implements PrivateKey {
    private final int[] s;

    public NewHopePrivateKey(int[] s) {
        this.s = s;
    }

    @Override
    public int[] s() {
        return s;
    }
}
