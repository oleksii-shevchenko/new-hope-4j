package dev.flanker.newhope.chiper.domain;

import dev.flanker.newhope.api.PrivateKey;

import java.util.Arrays;

public class NewHopePrivateKey implements PrivateKey {
    private final int[] s;

    public NewHopePrivateKey(int[] s) {
        this.s = Arrays.copyOf(s, s.length);
    }

    public int[] s() {
        return Arrays.copyOf(s, s.length);
    }
}
