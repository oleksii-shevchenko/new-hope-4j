package dev.flanker.newhope.internal;

import dev.flanker.newhope.keccak.Shake;
import dev.flanker.newhope.spec.NewHopeSpec;

import java.math.BigInteger;

public final class Poly {
    private Poly() { }

    public static int[] polyBitReverse(int[] polynomial) {
        int[] reverse = new int[polynomial.length];
        int logLength = Integer.highestOneBit(polynomial.length);
        for (int i = 0; i < polynomial.length; i++) {
            reverse[bitsReverse(i, logLength)] = polynomial[i];
        }
        return reverse;
    }

    private static int bitsReverse(int x, int length) {
        return Integer.reverse(x) >>> (Integer.SIZE - length);
    }

    public static int hw(int x) {
        return Integer.bitCount(x);
    }

    public static int[] scalarMultiplication(int[] x, int[] y, int q) {
        checkLength(x.length, y.length);
        int[] z = new int[x.length];
        for (int i = 0; i < z.length; i++) {
            z[i] = Integer.remainderUnsigned(x[i] * y[i], q);
        }
        return z;
    }

    public static int[] add(int[] x, int[] y, int q) {
        assert x.length == y.length;
        int[] z = new int[x.length];
        for (int i = 0; i < z.length; i++) {
            z[i] = Integer.remainderUnsigned(x[i] + y[i], q);
        }
        return z;
    }

    public static int[] subtract(int[] x, int[] y, int q) {
        assert x.length == y.length;
        int[] z = new int[x.length];
        for (int i = 0; i < z.length; i++) {
            z[i] = Integer.remainderUnsigned(x[i] - y[i], q);
        }
        return z;
    }

    public static int[] genA(byte[] seed, NewHopeSpec spec) {
        int[] a = new int[spec.n()];
        long[] state = new long[Shake.STATE_SIZE];
        byte[] buffer = new byte[Shake.SHAKE128_RATE];

        byte[] extendedSeed = new byte[33];
        System.arraycopy(seed, 0, extendedSeed, 0, seed.length);

        for (int i = 0; i < (spec.n() >>> 6) - 1; i++) {
            int counter = 0;
            extendedSeed[32] = (byte) i;
            Shake.shake128Absorb(state, extendedSeed);
            while (counter < 64) {
                Shake.shake128SqueezeBlocks(buffer, 1, state);
                for (int j = 0; j < Shake.SHAKE128_RATE && counter < 64; j += 2) {
                    int val = Byte.toUnsignedInt(buffer[j]) | (Byte.toUnsignedInt(buffer[j + 1]) << 8);
                    if (val < 5 * spec.q()) {
                        a[64 * i + counter] = val;
                        counter++;
                    }
                }
            }
        }

        return a;
    }

    public static int[] nnt(int[] polynomial, NewHopeSpec spec) {
        return null;
    }

    private static void checkLength(int xLength, int yLength) {
        if (xLength != yLength) {
            throw new RuntimeException("Arrays must have the same length.");
        }
    }

    public static int[] inverseNnt(int[] poly, NewHopeSpec spec) {
        return null;
    }
}
