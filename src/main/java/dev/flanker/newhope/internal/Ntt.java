package dev.flanker.newhope.internal;

import dev.flanker.newhope.spec.NewHopeSpec;

import java.util.Map;

public final class Ntt {
    private static Map<NewHopeSpec, int[][]> PRECOMPUTED = Map.of(
            NewHopeSpec.NEW_HOPE_512, precomputedNttCoefficient(NewHopeSpec.NEW_HOPE_512),
            NewHopeSpec.NEW_HOPE_1024, precomputedNttCoefficient(NewHopeSpec.NEW_HOPE_1024)
    );

    private static Map<NewHopeSpec, int[][]> INVERSE_PRECOMPUTED = Map.of(
            NewHopeSpec.NEW_HOPE_512, precomputedInverseNttCoefficient(NewHopeSpec.NEW_HOPE_512),
            NewHopeSpec.NEW_HOPE_1024, precomputedInverseNttCoefficient(NewHopeSpec.NEW_HOPE_1024)
    );

    private Ntt() { }

    public static int[] direct(int[] poly, NewHopeSpec spec) {
        if (!PRECOMPUTED.containsKey(spec)) {
            throw new RuntimeException("Unsupported specification");
        }
        return genericNtt(poly, PRECOMPUTED.get(spec), spec);
    }

    public static int[] inverse(int[] poly, NewHopeSpec spec) {
        if(!INVERSE_PRECOMPUTED.containsKey(spec)) {
            throw new RuntimeException("Unsupported specification");
        }
        return genericNtt(poly, INVERSE_PRECOMPUTED.get(spec), spec);
    }

    private static int[] genericNtt(int[] poly, int[][] table, NewHopeSpec spec) {
        int[] image = new int[spec.n];
        for (int i = 0; i < spec.n; i++) {
            image[i] = stepNtt(table, i, poly, spec);
        }
        return image;
    }

    private static int stepNtt(int[][] table, int i, int[] poly, NewHopeSpec spec) {
        int coefficient = 0;
        for (int j = 0; j < spec.n; j++) {
            int multiplication = Integer.remainderUnsigned(table[i][j] * poly[j], spec.q);
            coefficient = Integer.remainderUnsigned(coefficient + multiplication, spec.q);
        }
        return coefficient;
    }

    private static int pow(int x, int y, int q) {
        int z = 1;
        int amplitude = x;
        for (int i = 0; i < Integer.highestOneBit(y); i++) {
            if (((y >>> i) & 0x1) == 0x1) {
                z = Integer.remainderUnsigned(z * amplitude, q);
            }
            amplitude = Integer.remainderUnsigned(amplitude * amplitude, q);
        }
        return z;
    }

    private static int[][] precomputedNttCoefficient(NewHopeSpec spec) {
        int[][] precomputed = new int[spec.n][spec.n];
        for (int i = 0; i < spec.n; i++) {
            for (int j = 0; j < spec.n; j++) {
                int gammaPower = pow(spec.g, j, spec.q);
                int omegaPower = pow(spec.w, i * j, spec.q);
                precomputed[i][j] = Integer.remainderUnsigned(gammaPower * omegaPower, spec.q);
            }
        }
        return precomputed;
    }

    private static int[][] precomputedInverseNttCoefficient(NewHopeSpec spec) {
        int[][] precomputed = new int[spec.n][spec.n];
        for (int i = 0; i < spec.n; i++) {
            for (int j = 0; j < spec.n; j++) {
                int gammaPower = pow(spec.invG, i, spec.q);
                int omegaPower = pow(spec.invW, i * j, spec.q);
                int multiplicationReminder = Integer.remainderUnsigned(gammaPower * omegaPower, spec.q);
                precomputed[i][j] = Integer.remainderUnsigned(multiplicationReminder * spec.invN, spec.q);
            }
        }
        return precomputed;
    }
}
