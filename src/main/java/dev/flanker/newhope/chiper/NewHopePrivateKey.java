package dev.flanker.newhope.chiper;

import dev.flanker.newhope.api.PrivateKey;
import dev.flanker.newhope.internal.Encoder;
import dev.flanker.newhope.spec.NewHopeSpec;

public final class NewHopePrivateKey implements PrivateKey {
    private final int[] s;

    public NewHopePrivateKey(int[] s) {
        this.s = s;
    }

    @Override
    public int[] s() {
        return s;
    }

    @Override
    public byte[] encode() {
        return Encoder.encodePolynomial(s, NewHopeSpec.Q);
    }
}
