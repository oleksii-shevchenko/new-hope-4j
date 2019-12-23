package dev.flanker.newhope.internal;

import dev.flanker.newhope.keccak.Shake;
import dev.flanker.newhope.spec.NewHopeSpec;

public final class Poly {
    private static int EXTENDED_SEED_SIZE = 33;

    private Poly() { }

    public static int[] polyBitReverse(int[] polynomial, NewHopeSpec spec) {
        int[] reverse = new int[spec.n];
        for (int i = 0; i < spec.n; i++) {
            reverse[bitsReverse(i, spec.logN)] = polynomial[i];
        }
        return reverse;
    }

    public static int[] scalarMultiplication(int[] x, int[] y, int q) {
        checkLength(x, y);
        int[] z = new int[x.length];
        for (int i = 0; i < z.length; i++) {
            z[i] = Integer.remainderUnsigned(x[i] * y[i], q);
        }
        return z;
    }

    public static int[] add(int[] x, int[] y, int q) {
        checkLength(x, y);
        int[] z = new int[x.length];
        for (int i = 0; i < z.length; i++) {
            z[i] = Integer.remainderUnsigned(x[i] + y[i], q);
        }
        return z;
    }

    public static int[] subtract(int[] x, int[] y, int q) {
        checkLength(x, y);
        int[] z = new int[x.length];
        for (int i = 0; i < z.length; i++) {
            if (x[i] >= y[i]) {
                z[i] = Integer.remainderUnsigned(x[i] - y[i], q);
            } else {
                z[i] = Integer.remainderUnsigned(x[i] + q - y[i], q);
            }
        }
        return z;
    }

    public static int[] genA(byte[] seed, NewHopeSpec spec) {
        int[] a = new int[spec.n];
        long[] state = new long[Shake.STATE_SIZE];
        byte[] buffer = new byte[Shake.SHAKE128_RATE];

        byte[] extendedSeed = new byte[EXTENDED_SEED_SIZE];
        System.arraycopy(seed, 0, extendedSeed, 0, seed.length);

        for (int i = 0; i < (spec.n >>> 6); i++) {
            int counter = 0;
            extendedSeed[32] = (byte) i;
            Shake.shake128Absorb(state, extendedSeed);
            while (counter < 64) {
                Shake.shake128SqueezeBlocks(buffer, 1, state);
                for (int j = 0; j < Shake.SHAKE128_RATE && counter < 64; j += 2) {
                    int val = Byte.toUnsignedInt(buffer[j]) | (Byte.toUnsignedInt(buffer[j + 1]) << 8);
                    if (val < 5 * spec.q) {
                        a[64 * i + counter] = Integer.remainderUnsigned(val, spec.q);
                        counter++;
                    }
                }
            }
        }
        return a;
    }

    static int hw(int x) {
        return Integer.bitCount(x);
    }

    static int restrictedHw(int x) {
        return Integer.bitCount(x & 0xFF);
    }

    private static int bitsReverse(int x, int length) {
        return Integer.reverse(x) >>> (Integer.SIZE - length);
    }

    private static void checkLength(int[] x, int[] y) {
        assert x.length == y.length : "Arrays representing the polynomials must be the same length";
    }
}
