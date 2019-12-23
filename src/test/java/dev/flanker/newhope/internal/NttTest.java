package dev.flanker.newhope.internal;

import dev.flanker.newhope.spec.NewHopeSpec;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class NttTest {
    private static final NewHopeSpec spec = NewHopeSpec.NEW_HOPE_1024;
    @Test
    public void consistencyTest() {
        int[] poly = ThreadLocalRandom.current()
                .ints()
                .filter(i -> i >= 0)
                .map(i -> i % spec.q)
                .limit(spec.n)
                .toArray();

        int[] inverse = Ntt.inverse(Ntt.direct(poly, spec), spec);
        assertArrayEquals(poly, inverse);
    }
}