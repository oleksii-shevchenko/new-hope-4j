/*
 * Based on the public domain implementation in
 * crypto_hash/keccakc512/simple/ from http://bench.cr.yp.to/supercop.html
 * by Ronny Van Keer,
 * the public domain "TweetFips202" implementation
 * from https://twitter.com/tweetfips202
 * by Gilles Van Assche, Daniel J. Bernstein, and Peter Schwabe and
 * the official New Hope implementation.
 */

package dev.flanker.newhope.keccak;

import static java.lang.System.arraycopy;
import static java.util.Arrays.fill;

public class Shake {
    private static final int ROUNDS = 24;

    private static final int STATE_SIZE = 25;

    private static final int SHAKE128_RATE = 168;

    private static final int SHAKE256_RATE = 136;

    private static final int TEMP_STORAGE_SIZE = 200;

    private static final ThreadLocal<byte[]> THREAD_LOCAL_TEMP_STORAGE = ThreadLocal.withInitial(() -> new byte[TEMP_STORAGE_SIZE]);

    private static final long[] KECCAK_F_ROUND_CONSTANTS = {
            0x0000000000000001L,
            0x0000000000008082L,
            0x800000000000808aL,
            0x8000000080008000L,
            0x000000000000808bL,
            0x0000000080000001L,
            0x8000000080008081L,
            0x8000000000008009L,
            0x000000000000008aL,
            0x0000000000000088L,
            0x0000000080008009L,
            0x000000008000000aL,
            0x000000008000808bL,
            0x800000000000008bL,
            0x8000000000008089L,
            0x8000000000008003L,
            0x8000000000008002L,
            0x8000000000000080L,
            0x000000000000800aL,
            0x800000008000000aL,
            0x8000000080008081L,
            0x8000000000008080L,
            0x0000000080000001L,
            0x8000000080008008L
    };

    private static long rotate(long x, int offset) {
        return ((x << offset) ^ (x >>> (64-offset)));
    }

    /**
     * Load 8 bytes into long in little-endian order.
     *
     * @param bytes Source array
     * @param offset Source offset
     * @return The loaded long
     */
    private static long load(final byte[] bytes, int offset) {
        long loaded = 0;
        for (int i = 0; i < 8; ++i) {
            loaded |= Byte.toUnsignedLong(bytes[offset + i]) << 8 * i;
        }
        return loaded;
    }

    /**
     * Restore bytes for the long to byte array in little-endian order.
     *
     * @param bytes Destination array
     * @param offset Destination offset
     * @param loaded Loaded bytes
     */
    private static void restore(byte[] bytes, int offset, long loaded) {
        for(int i=0; i<8; i++) {
            bytes[offset + i] = (byte) loaded;
            loaded >>>= 8;
        }
    }

    private static void keccakF1600StatePermute(long[] state)
    {
        int round;

        long Aba, Abe, Abi, Abo, Abu;
        long Aga, Age, Agi, Ago, Agu;
        long Aka, Ake, Aki, Ako, Aku;
        long Ama, Ame, Ami, Amo, Amu;
        long Asa, Ase, Asi, Aso, Asu;
        long BCa, BCe, BCi, BCo, BCu;
        long Da, De, Di, Do, Du;
        long Eba, Ebe, Ebi, Ebo, Ebu;
        long Ega, Ege, Egi, Ego, Egu;
        long Eka, Eke, Eki, Eko, Eku;
        long Ema, Eme, Emi, Emo, Emu;
        long Esa, Ese, Esi, Eso, Esu;

        //copyFromState(A, state)
        Aba = state[ 0];
        Abe = state[ 1];
        Abi = state[ 2];
        Abo = state[ 3];
        Abu = state[ 4];
        Aga = state[ 5];
        Age = state[ 6];
        Agi = state[ 7];
        Ago = state[ 8];
        Agu = state[ 9];
        Aka = state[10];
        Ake = state[11];
        Aki = state[12];
        Ako = state[13];
        Aku = state[14];
        Ama = state[15];
        Ame = state[16];
        Ami = state[17];
        Amo = state[18];
        Amu = state[19];
        Asa = state[20];
        Ase = state[21];
        Asi = state[22];
        Aso = state[23];
        Asu = state[24];

        for( round = 0; round < ROUNDS; round += 2 ) {
            //    prepareTheta
            BCa = Aba^Aga^Aka^Ama^Asa;
            BCe = Abe^Age^Ake^Ame^Ase;
            BCi = Abi^Agi^Aki^Ami^Asi;
            BCo = Abo^Ago^Ako^Amo^Aso;
            BCu = Abu^Agu^Aku^Amu^Asu;

            //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
            Da = BCu^rotate(BCe, 1);
            De = BCa^rotate(BCi, 1);
            Di = BCe^rotate(BCo, 1);
            Do = BCi^rotate(BCu, 1);
            Du = BCo^rotate(BCa, 1);

            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = rotate(Age, 44);
            Aki ^= Di;
            BCi = rotate(Aki, 43);
            Amo ^= Do;
            BCo = rotate(Amo, 21);
            Asu ^= Du;
            BCu = rotate(Asu, 14);
            Eba =   BCa ^((~BCe)&  BCi );
            Eba ^= KECCAK_F_ROUND_CONSTANTS[round];
            Ebe =   BCe ^((~BCi)&  BCo );
            Ebi =   BCi ^((~BCo)&  BCu );
            Ebo =   BCo ^((~BCu)&  BCa );
            Ebu =   BCu ^((~BCa)&  BCe );

            Abo ^= Do;
            BCa = rotate(Abo, 28);
            Agu ^= Du;
            BCe = rotate(Agu, 20);
            Aka ^= Da;
            BCi = rotate(Aka,  3);
            Ame ^= De;
            BCo = rotate(Ame, 45);
            Asi ^= Di;
            BCu = rotate(Asi, 61);
            Ega =   BCa ^((~BCe)&  BCi );
            Ege =   BCe ^((~BCi)&  BCo );
            Egi =   BCi ^((~BCo)&  BCu );
            Ego =   BCo ^((~BCu)&  BCa );
            Egu =   BCu ^((~BCa)&  BCe );

            Abe ^= De;
            BCa = rotate(Abe,  1);
            Agi ^= Di;
            BCe = rotate(Agi,  6);
            Ako ^= Do;
            BCi = rotate(Ako, 25);
            Amu ^= Du;
            BCo = rotate(Amu,  8);
            Asa ^= Da;
            BCu = rotate(Asa, 18);
            Eka =   BCa ^((~BCe)&  BCi );
            Eke =   BCe ^((~BCi)&  BCo );
            Eki =   BCi ^((~BCo)&  BCu );
            Eko =   BCo ^((~BCu)&  BCa );
            Eku =   BCu ^((~BCa)&  BCe );

            Abu ^= Du;
            BCa = rotate(Abu, 27);
            Aga ^= Da;
            BCe = rotate(Aga, 36);
            Ake ^= De;
            BCi = rotate(Ake, 10);
            Ami ^= Di;
            BCo = rotate(Ami, 15);
            Aso ^= Do;
            BCu = rotate(Aso, 56);
            Ema =   BCa ^((~BCe)&  BCi );
            Eme =   BCe ^((~BCi)&  BCo );
            Emi =   BCi ^((~BCo)&  BCu );
            Emo =   BCo ^((~BCu)&  BCa );
            Emu =   BCu ^((~BCa)&  BCe );

            Abi ^= Di;
            BCa = rotate(Abi, 62);
            Ago ^= Do;
            BCe = rotate(Ago, 55);
            Aku ^= Du;
            BCi = rotate(Aku, 39);
            Ama ^= Da;
            BCo = rotate(Ama, 41);
            Ase ^= De;
            BCu = rotate(Ase,  2);
            Esa =   BCa ^((~BCe)&  BCi );
            Ese =   BCe ^((~BCi)&  BCo );
            Esi =   BCi ^((~BCo)&  BCu );
            Eso =   BCo ^((~BCu)&  BCa );
            Esu =   BCu ^((~BCa)&  BCe );

            //    prepareTheta
            BCa = Eba^Ega^Eka^Ema^Esa;
            BCe = Ebe^Ege^Eke^Eme^Ese;
            BCi = Ebi^Egi^Eki^Emi^Esi;
            BCo = Ebo^Ego^Eko^Emo^Eso;
            BCu = Ebu^Egu^Eku^Emu^Esu;

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da = BCu^rotate(BCe, 1);
            De = BCa^rotate(BCi, 1);
            Di = BCe^rotate(BCo, 1);
            Do = BCi^rotate(BCu, 1);
            Du = BCo^rotate(BCa, 1);

            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = rotate(Ege, 44);
            Eki ^= Di;
            BCi = rotate(Eki, 43);
            Emo ^= Do;
            BCo = rotate(Emo, 21);
            Esu ^= Du;
            BCu = rotate(Esu, 14);
            Aba =   BCa ^((~BCe)&  BCi );
            Aba ^= KECCAK_F_ROUND_CONSTANTS[round+1];
            Abe =   BCe ^((~BCi)&  BCo );
            Abi =   BCi ^((~BCo)&  BCu );
            Abo =   BCo ^((~BCu)&  BCa );
            Abu =   BCu ^((~BCa)&  BCe );

            Ebo ^= Do;
            BCa = rotate(Ebo, 28);
            Egu ^= Du;
            BCe = rotate(Egu, 20);
            Eka ^= Da;
            BCi = rotate(Eka, 3);
            Eme ^= De;
            BCo = rotate(Eme, 45);
            Esi ^= Di;
            BCu = rotate(Esi, 61);
            Aga =   BCa ^((~BCe)&  BCi );
            Age =   BCe ^((~BCi)&  BCo );
            Agi =   BCi ^((~BCo)&  BCu );
            Ago =   BCo ^((~BCu)&  BCa );
            Agu =   BCu ^((~BCa)&  BCe );

            Ebe ^= De;
            BCa = rotate(Ebe, 1);
            Egi ^= Di;
            BCe = rotate(Egi, 6);
            Eko ^= Do;
            BCi = rotate(Eko, 25);
            Emu ^= Du;
            BCo = rotate(Emu, 8);
            Esa ^= Da;
            BCu = rotate(Esa, 18);
            Aka =   BCa ^((~BCe)&  BCi );
            Ake =   BCe ^((~BCi)&  BCo );
            Aki =   BCi ^((~BCo)&  BCu );
            Ako =   BCo ^((~BCu)&  BCa );
            Aku =   BCu ^((~BCa)&  BCe );

            Ebu ^= Du;
            BCa = rotate(Ebu, 27);
            Ega ^= Da;
            BCe = rotate(Ega, 36);
            Eke ^= De;
            BCi = rotate(Eke, 10);
            Emi ^= Di;
            BCo = rotate(Emi, 15);
            Eso ^= Do;
            BCu = rotate(Eso, 56);
            Ama =   BCa ^((~BCe)&  BCi );
            Ame =   BCe ^((~BCi)&  BCo );
            Ami =   BCi ^((~BCo)&  BCu );
            Amo =   BCo ^((~BCu)&  BCa );
            Amu =   BCu ^((~BCa)&  BCe );

            Ebi ^= Di;
            BCa = rotate(Ebi, 62);
            Ego ^= Do;
            BCe = rotate(Ego, 55);
            Eku ^= Du;
            BCi = rotate(Eku, 39);
            Ema ^= Da;
            BCo = rotate(Ema, 41);
            Ese ^= De;
            BCu = rotate(Ese, 2);
            Asa =   BCa ^((~BCe)&  BCi );
            Ase =   BCe ^((~BCi)&  BCo );
            Asi =   BCi ^((~BCo)&  BCu );
            Aso =   BCo ^((~BCu)&  BCa );
            Asu =   BCu ^((~BCa)&  BCe );
        }

        //copyToState(state, A)
        state[ 0] = Aba;
        state[ 1] = Abe;
        state[ 2] = Abi;
        state[ 3] = Abo;
        state[ 4] = Abu;
        state[ 5] = Aga;
        state[ 6] = Age;
        state[ 7] = Agi;
        state[ 8] = Ago;
        state[ 9] = Agu;
        state[10] = Aka;
        state[11] = Ake;
        state[12] = Aki;
        state[13] = Ako;
        state[14] = Aku;
        state[15] = Ama;
        state[16] = Ame;
        state[17] = Ami;
        state[18] = Amo;
        state[19] = Amu;
        state[20] = Asa;
        state[21] = Ase;
        state[22] = Asi;
        state[23] = Aso;
        state[24] = Asu;
    }

    /**
     * Absorb step of Keccak.
     * Non-incremental, starts by zeroeing the state.
     *
     * @param state Keccak state
     * @param rate Rate in bytes
     * @param message Input message
     * @param parameter Domain-separation byte for different Keccak-derived functions
     */
    private static void keccakAbsorb(final long[] state, int rate, final byte[] message, byte parameter) {
        for (int i = 0; i < STATE_SIZE; i++) {
            state[i] = 0;
        }

        for (int i = 0; i < message.length / rate; i++) {
            for (int j = 0; j < (rate >>> 3); j++) {
                state[j] ^= load(message, rate * i + 8 * j);
            }
            keccakF1600StatePermute(state);
        }

        byte[] temp = THREAD_LOCAL_TEMP_STORAGE.get();

        fill(temp, (byte) 0);

        int remaining = message.length % rate;
        int offset = message.length - remaining;

        arraycopy(message, offset, temp, 0, remaining);

        temp[remaining] = parameter;
        temp[rate - 1] |= 128;

        for (int i = 0; i < (rate >>> 3); i++) {
            state[i] ^= load(temp, +8 * i);
        }

        fill(temp, (byte) 0);
    }

    /**
     * Squeeze step of Keccak. Squeezes full blocks of r bytes each.
     * Modifies the state. Can be called multiple times to keep squeezing,
     * i.e., is incremental.
     *
     * @param hash Output blocks array
     * @param blocks Number of blocks to be squeezed
     * @param state Keccak state
     * @param rate Rate in bytes
     */
    private static void keccakSqueezeBlocks(byte[] hash, int blocks, long[] state, int rate) {
        for (int i = 0; i < blocks; i++) {
            keccakF1600StatePermute(state);
            for (int j = 0; j < (rate >>> 3); j++) {
                restore(hash, rate * i + 8 * j, state[j]);
            }
        }
    }

    /**
     * Absorb step of the SHAKE128 XOF.
     * Non-incremental, starts by zeroeing the state.
     *
     * @param state Keccak step
     * @param input Input message
     */
    private static void shake128Absorb(long[] state, byte[] input) {
        keccakAbsorb(state, SHAKE128_RATE, input, (byte) 0x1F);
    }

    /**
     * Squeeze step of SHAKE128 XOF. Squeezes full blocks of SHAKE128_RATE bytes each.
     * Modifies the state. Can be called multiple times to keep squeezing,
     * i.e., is incremental.
     *
     * @param output Output blocks array
     * @param blocks Number of blocks to be squeezed
     * @param state Keccak state
     */
    void shake128SqueezeBlocks(byte[] output, int blocks, long[] state) {
        keccakSqueezeBlocks(output, blocks, state, SHAKE128_RATE);
    }

    /**
     * SHAKE256 XOF with non-incremental API.
     *
     * @param output Output array
     * @param outputLength Requested output length in bytes
     * @param input Input array
     */
    public static void shake256(byte[] output, int outputLength, byte[] input) {
        long[] state = new long[STATE_SIZE];
        byte[] temp = new byte[SHAKE256_RATE];

        int blocks = outputLength / SHAKE256_RATE;

        keccakAbsorb(state, SHAKE256_RATE, input, (byte) 0x1F);

        keccakSqueezeBlocks(output, blocks, state, SHAKE256_RATE);

        int remaining = outputLength % SHAKE256_RATE;
        if(remaining > 0) {
            keccakSqueezeBlocks(temp, 1, state, SHAKE256_RATE);
            arraycopy(temp, 0, output, SHAKE256_RATE * blocks, remaining);
        }
    }

    public static void shake256(byte[] output, byte[] input) {
        shake256(output, output.length, input);
    }
}
