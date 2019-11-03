package dev.flanker.newhope.internal;

import java.util.Arrays;

public class Encoder {
    public static byte[] encodePublicKey(int[] poly, byte[] publicSeed, int q) {
        byte[] r = new byte[(7 * poly.length) / 4 + 32];
        byte[] encodedPoly = encodePolynomial(poly, q);

        System.arraycopy(encodedPoly, 0, r, 0, encodedPoly.length);
        System.arraycopy(publicSeed, 0, r, encodedPoly.length, 32);

        return r;
    }

    public static byte[] encodePolynomial(int[] poly, int q) {
        byte[] r = new byte[(7 * poly.length) / 4];

        for (int i = 0; i < (poly.length / 4); i++) {
            int t0 = poly[4 * i] % q;
            int t1 = poly[4 * i + 1] % q;
            int t2 = poly[4 * i + 2] % q;
            int t3 = poly[4 * i + 3] % q;

            r[7 * i] = (byte) t0;
            r[7 * i + 1] = (byte) ((t0 >>> 8) | (t1 << 6));
            r[7 * i + 2] = (byte) (t1 >>> 2);
            r[7 * i + 3] = (byte) ((t1 >>> 10) | (t2 << 4));
            r[7 * i + 4] = (byte) (t2 >>> 4);
            r[7 * i + 5] = (byte) ((t2 >>> 12) | (t3 << 2));
            r[7 * i + 6] = (byte) (t3 >>> 6);
        }

        return r;
    }

    public static int[] encodeMessage(byte[] message, int n, int q) {
        int[] v = new int[n];
        for (int i = 0; i < 32; i++) {
            for (int j = 0; j < 8; j++) {
                int value = (-((message[i] >>> j) & 1)) & (q >>> 1) ;
                v[8 * i + j] = value;
                v[8 * i + j + 256] = value;
                if (n == 1024) {
                    v[8 * i + j + 512] = value;
                    v[8 * i + j + 768] = value;
                }
            }
        }
        return v;
    }

    public static byte[] compress(int[] poly, int q) {
        int k = 0;

        byte[] temp = new byte[8];
        byte[] h = new byte[3 * poly.length / 8];

        for (int l = 0; l < (poly.length >>> 3); l++) {
            int i = l << 3;
            for (int j = 0; j < 8; j++) {
                temp[j] = (byte) ((poly[i + j] % q) << 3);
                temp[j] = (byte) (Integer.divideUnsigned(Byte.toUnsignedInt(temp[j]) + (q >>> 1), q) & 7);
            }
            h[k] = (byte) (temp[0] | (temp[1] << 3) | (temp[2] << 6));
            h[k + 1] = (byte) ((Byte.toUnsignedInt(temp[2]) >>> 2) | (temp[3] << 1) | (temp[4] << 4) | (temp[5] << 7));
            h[k + 2] = (byte) ((Byte.toUnsignedInt(temp[5]) >>> 1) | (temp[6] << 2) | (temp[7] << 5));
            k += 3;
        }

        return h;
    }

    public static byte[] encodeCiphertext(int[] poly, byte[] h, int q) {
        byte[] encodedPoly = encodePolynomial(poly, q);
        byte[] ciphertext = new byte[encodedPoly.length + h.length];

        System.arraycopy(encodedPoly, 0, ciphertext, 0, encodedPoly.length);
        System.arraycopy(h, 0, ciphertext, encodedPoly.length, h.length);

        return ciphertext;
    }

    public static int[] decompress(byte[] h, int n, int q) {
        int k = 0;
        int[] r = new int[n];
        for (int l = 0; l < (n >>> 3); l++) {
            int i = l << 3;
            r[i] = h[k] & 7;
            r[i + 1] = (Byte.toUnsignedInt(h[k]) >>> 3) & 7;
            r[i + 1] = (Byte.toUnsignedInt(h[k]) >>> 6) | ((Byte.toUnsignedInt(h[k + 1]) << 2) & 4);
            r[i + 1] = (Byte.toUnsignedInt(h[k + 1]) >>> 1) & 7;
            r[i + 1] = (Byte.toUnsignedInt(h[k + 1]) >>> 4) & 7;
            r[i + 1] = (Byte.toUnsignedInt(h[k + 1]) >>> 7) | ((Byte.toUnsignedInt(h[k + 2]) << 1) & 6);
            r[i + 1] = (Byte.toUnsignedInt(h[k + 2]) >>> 2) & 7;
            r[i + 1] = (Byte.toUnsignedInt(h[k + 2]) >>> 5);
            k += 3;
            for (int j = 0; j < 8; j++) {
                r[i + j] = (r[i + j] * q + 4) >>> 3;
            }
        }
        return r;
    }

    public static byte[] decodeMessage(int[] poly, int q) {
        byte[] message = new byte[32];
        for (int i = 0; i < 256; i++) {
            int t = Math.abs((poly[i] % q) - ((q - 1) >>> 1)) +
                    Math.abs((poly[i + 256] % q) - ((q - 1) >>> 1));
            if (poly.length == 1024) {
                t += Math.abs((poly[i + 512] % q) - ((q - 1) >>> 1)) +
                        Math.abs((poly[i + 768] % q) - ((q - 1) >>> 1)) - q;
            } else {
                t -= (q >>> 1);
            }
            t = t >>> 15;
            message[i >>> 3] = (byte) (message[i >>> 3] | (t << (i & 7)));
        }
        return message;
    }

    public static Pair<int[], byte[]> decodeCihpertext(byte[] ciphertext, int n) {
        int[] poly = decodePolynomial(Arrays.copyOfRange(ciphertext, 0, 7 * n / 4), n);
        return new Pair<>(poly, Arrays.copyOfRange(ciphertext, 7 * n / 4, ciphertext.length));
    }

    private static int[] decodePolynomial(byte[] v, int n) {
        int[] r = new int[n];
        for (int i = 0; i < (n >>> 2); i++) {
            r[4 * i] = Byte.toUnsignedInt(v[7 * i]) | ((Byte.toUnsignedInt(v[7 * i + 1]) & 0x3f) << 8);
            r[4 * i + 1] = (Byte.toUnsignedInt(v[7 * i + 1]) >>> 6) | (Byte.toUnsignedInt(v[7 * i + 2]) << 2) | ((Byte.toUnsignedInt(v[7 * i + 3]) & 0x3f) << 10);
            r[4 * i + 2] = (Byte.toUnsignedInt(v[7 * i + 3]) >>> 4) | (Byte.toUnsignedInt(v[7 * i + 4]) << 4) | ((Byte.toUnsignedInt(v[7 * i + 5]) & 0x03) << 12);
            r[4 * i + 3] = (Byte.toUnsignedInt(v[7 * i + 5]) >>> 2) | (Byte.toUnsignedInt(v[7 * i + 6]) << 6);
        }
        return r;
    }

    public static class Pair<T, K> {
        private final T left;
        private final K right;

        public Pair(T left, K right) {
            this.left = left;
            this.right = right;
        }

        public T getLeft() {
            return left;
        }

        public K getRight() {
            return right;
        }
    }
}
