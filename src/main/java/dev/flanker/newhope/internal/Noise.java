package dev.flanker.newhope.internal;

import dev.flanker.newhope.keccak.Shake;
import dev.flanker.newhope.spec.NewHopeSpec;

import java.security.SecureRandom;


public final class Noise {
    private static int SEED_LENGTH = 32;
    private static int EXT_SEED_SIZE = 34;
    private static int BUFFER_SIZE = 128;

    private Noise() { }

    public static int[] sample(byte[] seed, int nonce, NewHopeSpec spec) {
        return sample(seed, nonce, spec.q, spec.n);
    }

    public static int[] sample(byte[] seed, int nonce, int q, int n) {
        assert seed.length == SEED_LENGTH : "Wrong seed length!";

        int[] r = new int[n];
        byte[] buffer = new byte[BUFFER_SIZE];
        byte[] extendedSeed = new byte[EXT_SEED_SIZE];

        System.arraycopy(seed, 0, extendedSeed, 0, seed.length);
        extendedSeed[32] = (byte) nonce;

        for (int i = 0; i < (n >>> 6); i++) {
            extendedSeed[33] = (byte) i;
            Shake.shake256(buffer, extendedSeed);
            for (int j = 0; j < 64; j++) {
                int a = buffer[2 * j    ];
                int b = buffer[2 * j + 1];
                r[64 * i + j] = Integer.remainderUnsigned(Poly.hw(a) + q - Poly.hw(b), q);
            }
        }

        return r;
    }

    public static byte[] randomBytes(SecureRandom secureRandom, int size) {
        byte[] bytes = new byte[size];
        secureRandom.nextBytes(bytes);
        return bytes;
    }
}
