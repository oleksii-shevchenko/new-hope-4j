package dev.flanker.newhope.internal;

import dev.flanker.newhope.spec.NewHopeSpec;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class PolyTest {
    private static final NewHopeSpec spec = NewHopeSpec.NEW_HOPE_1024;

    @Test
    public void genAConsistencyTest() {
        byte[] publicSeed = new byte[Encoder.PUBLIC_SEED_LENGTH];
        ThreadLocalRandom.current().nextBytes(publicSeed);
        assertArrayEquals(Poly.genA(publicSeed, spec), Poly.genA(publicSeed, spec));
    }
}