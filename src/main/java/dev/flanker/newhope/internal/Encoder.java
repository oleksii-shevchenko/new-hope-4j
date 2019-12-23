package dev.flanker.newhope.internal;

import dev.flanker.newhope.chiper.domain.NewHopePublicKey;
import dev.flanker.newhope.internal.domain.DecodedCiphertext;
import dev.flanker.newhope.spec.NewHopeSpec;

import java.util.Arrays;

import static java.lang.Byte.toUnsignedInt;

public final class Encoder {
    private static final int MESSAGE_LENGTH = 32;
    public static final int PUBLIC_SEED_LENGTH = 32;

    private Encoder() { }

    public static byte[] encodePolynomial(int[] poly, NewHopeSpec spec) {
        byte[] r = new byte[encodedPolynomialLength(spec)];
        for (int i = 0; i < (spec.n >>> 2); i++) {
            int t0 = Integer.remainderUnsigned(poly[4 * i    ], spec.q);
            int t1 = Integer.remainderUnsigned(poly[4 * i + 1], spec.q);
            int t2 = Integer.remainderUnsigned(poly[4 * i + 2], spec.q);
            int t3 = Integer.remainderUnsigned(poly[4 * i + 3], spec.q);

            r[7 * i    ] = (byte) t0;
            r[7 * i + 1] = (byte) ((t0 >>> 8) | (t1 << 6));
            r[7 * i + 2] = (byte) (t1 >>> 2);
            r[7 * i + 3] = (byte) ((t1 >>> 10) | (t2 << 4));
            r[7 * i + 4] = (byte) (t2 >>> 4);
            r[7 * i + 5] = (byte) ((t2 >>> 12) | (t3 << 2));
            r[7 * i + 6] = (byte) (t3 >>> 6);
        }
        return r;
    }

    public static int[] decodePolynomial(byte[] v, NewHopeSpec spec) {
        int[] r = new int[spec.n];
        for (int i = 0; i < (spec.n >>> 2); i++) {
            r[4 * i    ] = (toUnsignedInt(v[7 * i])          ) | ((toUnsignedInt(v[7 * i + 1]) & 0x3f) << 8);
            r[4 * i + 1] = (toUnsignedInt(v[7 * i + 1]) >>> 6) | (toUnsignedInt(v[7 * i + 2]) << 2) | ((toUnsignedInt(v[7 * i + 3]) & 0x0f) << 10);
            r[4 * i + 2] = (toUnsignedInt(v[7 * i + 3]) >>> 4) | (toUnsignedInt(v[7 * i + 4]) << 4) | ((toUnsignedInt(v[7 * i + 5]) & 0x03) << 12);
            r[4 * i + 3] = (toUnsignedInt(v[7 * i + 5]) >>> 2) | (toUnsignedInt(v[7 * i + 6]) << 6);
        }
        return r;
    }

    public static byte[] encodePublicKey(int[] poly, byte[] publicSeed, NewHopeSpec spec) {
        assert publicSeed.length == PUBLIC_SEED_LENGTH : "Wrong public seed length";
        int encodedPolyLength = encodedPolynomialLength(spec);
        byte[] r = new byte[encodedPolyLength + PUBLIC_SEED_LENGTH];
        byte[] encodedPoly = encodePolynomial(poly, spec);
        System.arraycopy(encodedPoly, 0, r, 0, encodedPolyLength);
        System.arraycopy(publicSeed, 0, r, encodedPolyLength, PUBLIC_SEED_LENGTH);
        return r;
    }
    
    public static byte[] encodePublicKey(NewHopePublicKey pk, NewHopeSpec spec) {
        return encodePublicKey(pk.b(), pk.publicSeed(), spec);
    }
    
    public static NewHopePublicKey decodePublicKey(byte[] src, NewHopeSpec spec) {
        int[] b = decodePolynomial(src, spec);
        byte[] publicSeed = new byte[PUBLIC_SEED_LENGTH];
        System.arraycopy(src, encodedPolynomialLength(spec), publicSeed, 0, PUBLIC_SEED_LENGTH);
        return new NewHopePublicKey(b, publicSeed);
    }

    public static int[] encodeMessage(byte[] message, NewHopeSpec spec) {
        assert message.length == MESSAGE_LENGTH : "Wrong message length";
        int[] v = new int[spec.n];
        for (int i = 0; i < 32; i++) {
            for (int j = 0; j < 8; j++) {
                int value = (-((message[i] >>> j) & 0x1)) & (spec.q >>> 1);
                v[8 * i + j] = value;
                v[8 * i + j + 256] = value;
                if (spec.n == 1024) {
                    v[8 * i + j + 512] = value;
                    v[8 * i + j + 768] = value;
                }
            }
        }
        return v;
    }

    public static byte[] decodeMessage(int[] poly, NewHopeSpec spec) {
        byte[] message = new byte[MESSAGE_LENGTH];
        for (int i = 0; i < 256; i++) {
            int t = flipAbs(poly[i], spec) + flipAbs(poly[i + 256], spec);
            if (spec.n == 1024) {
                t = flipAbs(poly[i + 512], spec) + flipAbs(poly[i + 768], spec);
                t = t - spec.q;
            } else {
                t = t - (spec.q >>> 1);
            }
            t = Integer.remainderUnsigned(t, 0xFFFF);
            message[i >>> 3] = (byte) (toUnsignedInt(message[i >>> 3]) | ((t >>> 15) << (i & 7)));
        }
        return message;
    }

    private static int flipAbs(int x, NewHopeSpec spec) {
        return Math.abs(Integer.remainderUnsigned(x, spec.q) - (spec.q >>> 1));
    }

    public static byte[] compress(int[] poly, NewHopeSpec spec) {
        int k = 0;
        int[] temp = new int[8];
        byte[] h = new byte[hLength(spec)];
        for (int i = 0; i < spec.n; i += 8) {
            for (int j = 0; j < 8; j++) {
                temp[j] = (Integer.remainderUnsigned(poly[i + j], spec.q));
                temp[j] = Integer.divideUnsigned((temp[j] << 3) + (spec.q >>> 1), spec.q) & 7;
            }
            h[k    ] = (byte) (temp[0] | (temp[1] << 3) | (temp[2] << 6));
            h[k + 1] = (byte) ((temp[2] >>> 2) | (temp[3] << 1) | (temp[4] << 4) | (temp[5] << 7));
            h[k + 2] = (byte) ((temp[5] >>> 1) | (temp[6] << 2) | (temp[7] << 5));
            k += 3;
        }
        return h;
    }

    public static int[] decompress(byte[] h, NewHopeSpec spec) {
        int k = 0;
        int[] r = new int[spec.n];
        for (int l = 0; l < (spec.n >>> 3); l++) {
            int i = l << 3;
            r[i    ] = toUnsignedInt(h[k]) & 7;
            r[i + 1] = (toUnsignedInt(h[k]) >>> 3) & 7;
            r[i + 2] = (toUnsignedInt(h[k]) >>> 6) | ((toUnsignedInt(h[k + 1]) << 2) & 4);
            r[i + 3] = (toUnsignedInt(h[k + 1]) >>> 1) & 7;
            r[i + 4] = (toUnsignedInt(h[k + 1]) >>> 4) & 7;
            r[i + 5] = (toUnsignedInt(h[k + 1]) >>> 7) | ((toUnsignedInt(h[k + 2]) << 1) & 6);
            r[i + 6] = (toUnsignedInt(h[k + 2]) >>> 2) & 7;
            r[i + 7] = (toUnsignedInt(h[k + 2]) >>> 5);
            k += 3;
            for (int j = 0; j < 8; j++) {
                r[i + j] = Integer.remainderUnsigned((r[i + j] * spec.q + 4) >>> 3, spec.q);
            }
        }
        return r;
    }

    public static byte[] encodeCiphertext(int[] poly, byte[] h, NewHopeSpec spec) {
        assert h.length == hLength(spec) : "Wrong h length";
        byte[] encodedPoly = encodePolynomial(poly, spec);
        byte[] ciphertext = new byte[encodedPolynomialLength(spec) + h.length];
        System.arraycopy(encodedPoly, 0, ciphertext, 0, encodedPolynomialLength(spec));
        System.arraycopy(h, 0, ciphertext, encodedPolynomialLength(spec) , h.length);
        return ciphertext;
    }

    public static DecodedCiphertext decodeCihpertext(byte[] encoded, NewHopeSpec spec) {
        int encodedPolyLength = encodedPolynomialLength(spec);
        int[] poly = decodePolynomial(Arrays.copyOfRange(encoded, 0, encodedPolyLength), spec);
        byte[] h = Arrays.copyOfRange(encoded, encodedPolyLength, encoded.length);
        return new DecodedCiphertext(poly, h);
    }

    private static int encodedPolynomialLength(NewHopeSpec spec) {
        return (7 * spec.n) >>> 2;
    }

    private static int hLength(NewHopeSpec spec) {
        return (3 * spec.n) >>> 3;
    }
}
