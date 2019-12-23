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

    @Test
    public void polyMultTest() {
        int[] x = new int[spec.n];
        x[0] = 1;
        x[1] = 2;
        x[2] = 3; // 1 + 2x + 3x^2

        int[] y = new int[spec.n];
        y[1] = 12;
        y[2] = 6; // 12y + 6y^2

        int[] z = new int[spec.n];
        z[1] = 12;
        z[2] = 30;
        z[3] = 48;
        z[4] = 18; // 12z + 30z^2 + 48z^3 + 18z^4

        int[] imX = Ntt.direct(x, spec);
        int[] imY = Ntt.direct(y, spec);

        int[] res = Ntt.inverse(Poly.scalarMultiplication(imX, imY, spec.q), spec);

        assertArrayEquals(z, res);
    }
}