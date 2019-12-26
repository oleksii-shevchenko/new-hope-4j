package dev.flanker.newhope.internal;

import dev.flanker.newhope.chiper.domain.NewHopePublicKey;
import dev.flanker.newhope.internal.domain.DecodedCiphertext;
import dev.flanker.newhope.spec.NewHopeSpec;
import org.junit.jupiter.api.Test;

import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class EncoderTest {
    private static final NewHopeSpec spec = NewHopeSpec.NEW_HOPE_1024;

    @Test
    public void polynomialEncodingTest() {
        int[] poly = ThreadLocalRandom.current()
                .ints()
                .filter(i -> i >= 0)
                .map(i -> i % spec.q)
                .limit(spec.n)
                .toArray();
        assertArrayEquals(poly, Encoder.decodePolynomial(Encoder.encodePolynomial(poly, spec), spec));
    }

    @Test
    public void publicKeyEncodingTest() {
        int[] poly = ThreadLocalRandom.current()
                .ints()
                .filter(i -> i >= 0)
                .map(i -> i % spec.q)
                .limit(spec.n)
                .toArray();

        byte[] publicSeed = new byte[Encoder.PUBLIC_SEED_LENGTH];
        ThreadLocalRandom.current().nextBytes(publicSeed);

        NewHopePublicKey pk = new NewHopePublicKey(poly, publicSeed);

        assertEquals(pk, Encoder.decodePublicKey(Encoder.encodePublicKey(pk, spec), spec));
    }

    @Test
    public void ciphertextEncodingTest() {
        int[] poly = ThreadLocalRandom.current()
                .ints()
                .filter(i -> i >= 0)
                .map(i -> i % spec.q)
                .limit(spec.n)
                .toArray();

        int[] compressed = ThreadLocalRandom.current()
                .ints()
                .filter(i -> i >= 0)
                .map(i -> i % spec.q)
                .limit(spec.n)
                .toArray();

        byte[] h = Encoder.compress(compressed, spec);

        DecodedCiphertext decodedCiphertext = Encoder.decodeCihpertext(Encoder.encodeCiphertext(poly, h, spec), spec);

        assertArrayEquals(poly, decodedCiphertext.getPoly());
        assertArrayEquals(h, decodedCiphertext.getH());
    }

    @Test
    public void messageEncodingTest() {
        byte[] message = new byte[32];
        ThreadLocalRandom.current().nextBytes(message);

        assertArrayEquals(message, Encoder.decodeMessage(Encoder.encodeMessage(message, spec), spec));
    }

    @Test
    public void compressConsistencyTest() {
        int[] poly = ThreadLocalRandom.current()
                .ints()
                .filter(i -> i >= 0)
                .map(i -> i % spec.q)
                .limit(spec.n)
                .toArray();

        int[] decompressed = Encoder.decompress(Encoder.compress(poly, spec), spec);

        for (int i =0; i < poly.length; i++) {
            System.out.println(poly[i] - decompressed[i]);
        }

    }
}