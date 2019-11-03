package dev.flanker.newhope.chiper;

import dev.flanker.newhope.api.Cipher;
import dev.flanker.newhope.api.KeyPair;
import dev.flanker.newhope.api.PrivateKey;
import dev.flanker.newhope.api.PublicKey;
import dev.flanker.newhope.internal.Encoder;
import dev.flanker.newhope.internal.Noise;
import dev.flanker.newhope.internal.Poly;
import dev.flanker.newhope.keccak.Shake;
import dev.flanker.newhope.spec.NewHopeSpec;

import java.security.SecureRandom;
import java.util.Arrays;

public class NewHopeCipher implements Cipher {
    private final SecureRandom secureRandom;
    private final NewHopeSpec spec;

    public NewHopeCipher(SecureRandom secureRandom, NewHopeSpec spec) {
        this.secureRandom = secureRandom;
        this.spec = spec;
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] seed = Noise.randomBytes(32, secureRandom);

        byte[] z = new byte[64];
        Shake.shake256(z, z.length, seed);

        byte[] publicSeed = Arrays.copyOfRange(z, 0, 32);
        byte[] noiseSeed = Arrays.copyOfRange(z, 32, 64);

        int[] s = Poly.polyBitReverse(Noise.sample(noiseSeed, 0, spec));
        int[] e = Poly.polyBitReverse(Noise.sample(noiseSeed, 1, spec));

        int[] aImage = Poly.genA(publicSeed, spec);
        int[] sImage = Poly.nnt(s, spec);
        int[] eImage = Poly.nnt(e, spec);
        int[] bImage = Poly.add(Poly.scalarMultiplication(aImage, sImage, spec.q()), eImage, spec.q());

        return new KeyPair(Encoder.encodePublicKey(bImage, publicSeed, spec.q()), Encoder.encodePolynomial(s, spec.q()));
    }

    @Override
    public byte[] encrypt(byte[] message, PublicKey key) {
        checkLength(message.length, 32);

        int q = spec.q();

        byte[] coin = new byte[32];
        secureRandom.nextBytes(coin);

        int[] aImage = Poly.genA(key.publicSeed(), spec);
        int[] eImage = Poly.nnt(Poly.polyBitReverse(Noise.sample(coin, 1, spec)), spec);

        int[] s = Poly.polyBitReverse(Noise.sample(coin, 0, spec));
        int[] error = Noise.sample(coin, 2, spec);

        int[] tImage = Poly.nnt(s, spec);
        int[] uImage = Poly.add(Poly.scalarMultiplication(aImage, tImage, q), eImage, q);

        int[] v = Encoder.encodeMessage(message, spec.n(), q);
        int[] p = Poly.add(Poly.add(Poly.inverseNnt(Poly.scalarMultiplication(key.b(), tImage, q), spec), error, q), v, q);
        byte[] h = Encoder.compress(p, spec.q());
        return Encoder.encodeCiphertext(uImage, h, q);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, PrivateKey key) {
        Encoder.Pair<int[], byte[]> decodeCiphertext = Encoder.decodeCihpertext(ciphertext);
        int[] v = Encoder.decompress(decodeCiphertext.getRight(), spec.n(), spec.q());
        int[] t = Poly.inverseNnt(Poly.scalarMultiplication(decodeCiphertext.getLeft(), key.s(), spec.q()), spec);
        byte[] message = Encoder.decodeMessage(Poly.subtract(v, t, spec.q()), spec.q());
        return new byte[0];
    }

    private void checkLength(int actual, int required) {
        if (actual != required) {
            throw new RuntimeException("Array has wrong length");
        }
    }
}
