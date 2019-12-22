package dev.flanker.newhope.chiper;

import dev.flanker.newhope.api.Cipher;
import dev.flanker.newhope.api.KeyFactory;
import dev.flanker.newhope.api.PrivateKey;
import dev.flanker.newhope.api.PublicKey;
import dev.flanker.newhope.api.domain.KeyPair;
import dev.flanker.newhope.chiper.domain.NewHopePrivateKey;
import dev.flanker.newhope.chiper.domain.NewHopePublicKey;
import dev.flanker.newhope.internal.Encoder;
import dev.flanker.newhope.internal.Noise;
import dev.flanker.newhope.internal.Ntt;
import dev.flanker.newhope.internal.Poly;
import dev.flanker.newhope.internal.domain.DecodedCiphertext;
import dev.flanker.newhope.keccak.Shake;
import dev.flanker.newhope.spec.NewHopeSpec;

import java.security.SecureRandom;
import java.util.Arrays;

public class NewHopeCipher implements Cipher {
    private static final int NOISE_LENGTH = 32;

    private final SecureRandom secureRandom;
    private final NewHopeSpec spec;

    private CipherMode mode;

    private NewHopePublicKey publicKey;
    private NewHopePrivateKey privateKey;

    public NewHopeCipher(SecureRandom secureRandom, NewHopeSpec spec) {
        this.secureRandom = secureRandom;
        this.spec = spec;
    }

    @Override
    public void dualMode(KeyPair pair) {
        assert pair != null : "Key pair wrapper must be not null";
        assert pair.getPrivateKey() != null && pair.getPublicKey() != null : "Encoded keys must be not null";

        this.mode = CipherMode.DUAL;
        this.publicKey = NewHopeKeyFactory.getInstance(spec).decodePublicKey(pair.getPublicKey());
        this.privateKey = NewHopeKeyFactory.getInstance(spec).decodePrivateKey(pair.getPrivateKey());
    }

    @Override
    public void encryptionMode(byte[] publicKey) {
        assert publicKey != null : "Public key must be not null";

        this.mode = CipherMode.ENCRYPTION;
        this.publicKey = NewHopeKeyFactory.getInstance(spec).decodePublicKey(publicKey);
        this.privateKey = null;
    }

    @Override
    public void encryptionMode(PublicKey publicKey) {
        assert publicKey != null : "Public key must be not null";
        assert publicKey instanceof NewHopePublicKey : "Wrong key type";

        NewHopePublicKey key = (NewHopePublicKey) publicKey;
        assert key.b() != null : "Polynomial b must be not null";
        assert key.b().length == spec.n : "Wrong polynomial length";
        assert key.publicSeed() != null : "Public seed must be not null";
        assert key.publicSeed().length == Encoder.PUBLIC_SEED_LENGTH : "Wrong public seed length";

        this.mode = CipherMode.ENCRYPTION;
        this.publicKey = key;
        this.privateKey = null;
    }

    @Override
    public void decryptionMode(byte[] privateKey) {
        assert privateKey != null : "Private key must be not null";

        this.mode = CipherMode.DECRYPTION;
        this.privateKey = NewHopeKeyFactory.getInstance(spec).decodePrivateKey(privateKey);
        this.publicKey = null;
    }

    @Override
    public void decryptionMode(PrivateKey privateKey) {
        assert privateKey != null : "Private key must be not null";
        assert privateKey instanceof NewHopePrivateKey : "Wrong key type";

        NewHopePrivateKey key = (NewHopePrivateKey) privateKey;
        assert key.s() != null : "Polynomial s must be not null";
        assert key.s().length == spec.n : "Wrong polynomial length";

        this.mode = CipherMode.DECRYPTION;
        this.privateKey = key;
        this.publicKey = null;
    }

    @Override
    public byte[] encrypt(byte[] message) {
        if (mode == CipherMode.DECRYPTION) {
            throw new RuntimeException("Wrong mode");
        }

        checkLength(message.length, 32);

        byte[] coin = new byte[32];
        secureRandom.nextBytes(coin);

        int[] aImage = Poly.genA(publicKey.publicSeed(), spec);
        int[] eImage = Ntt.direct(Poly.polyBitReverse(Noise.sample(coin, 1, spec), spec), spec);

        int[] s = Poly.polyBitReverse(Noise.sample(coin, 0, spec), spec);
        int[] error = Noise.sample(coin, 2, spec);

        int[] tImage = Ntt.direct(s, spec);
        int[] uImage = Poly.add(Poly.scalarMultiplication(aImage, tImage, spec.q), eImage, spec.q);

        int[] v = Encoder.encodeMessage(message, spec);
        int[] d = Ntt.inverse(Poly.scalarMultiplication(publicKey.b(), tImage, spec.q), spec);
        int[] p = Poly.add(Poly.add(v, error, spec.q), d, spec.q);
        byte[] h = Encoder.compress(p, spec);
        return Encoder.encodeCiphertext(uImage, h, spec);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        if (mode == CipherMode.ENCRYPTION) {
            throw new RuntimeException("Wrong mode");
        }

        DecodedCiphertext decodedCiphertext = Encoder.decodeCihpertext(ciphertext, spec);
        int[] v = Encoder.decompress(decodedCiphertext.getH(), spec);
        int[] t = Ntt.inverse(Poly.scalarMultiplication(decodedCiphertext.getPoly(), privateKey.s(), spec.q), spec);
        return Encoder.decodeMessage(Poly.subtract(v, t, spec.q), spec);
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[] seed = Noise.randomBytes(secureRandom, NOISE_LENGTH);

        byte[] z = new byte[64];
        Shake.shake256(z, seed);

        byte[] publicSeed = Arrays.copyOfRange(z, 0, 32);
        byte[] noiseSeed = Arrays.copyOfRange(z, 32, 64);

        int[] s = Poly.polyBitReverse(Noise.sample(noiseSeed, 0, spec), spec);
        int[] e = Poly.polyBitReverse(Noise.sample(noiseSeed, 1, spec), spec);

        int[] aImage = Poly.genA(publicSeed, spec);
        int[] sImage = Ntt.direct(s, spec);
        int[] eImage = Ntt.direct(e, spec);
        int[] bImage = Poly.add(Poly.scalarMultiplication(aImage, sImage, spec.q), eImage, spec.q);

        return new KeyPair(Encoder.encodePublicKey(bImage, publicSeed, spec), Encoder.encodePolynomial(s, spec));
    }

    @Override
    public KeyFactory getKeyFactory() {
        return NewHopeKeyFactory.getInstance(spec);
    }

    private void checkLength(int actual, int required) {
        if (actual != required) {
            throw new RuntimeException("Array has wrong length");
        }
    }
}