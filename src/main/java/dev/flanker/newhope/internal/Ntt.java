package dev.flanker.newhope.internal;

import dev.flanker.newhope.spec.NewHopeSpec;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Map;

public final class Ntt {
    private static Map<NewHopeSpec, int[][]> PRECOMPUTED = Map.of(
            NewHopeSpec.NEW_HOPE_512, loadTable("direct_512.csv", NewHopeSpec.NEW_HOPE_512),
            NewHopeSpec.NEW_HOPE_1024, loadTable("direct_1024.csv", NewHopeSpec.NEW_HOPE_1024)
    );

    private static Map<NewHopeSpec, int[][]> INVERSE_PRECOMPUTED = Map.of(
            NewHopeSpec.NEW_HOPE_512, loadTable("inverse_512.csv", NewHopeSpec.NEW_HOPE_512),
            NewHopeSpec.NEW_HOPE_1024, loadTable("inverse_1024.csv", NewHopeSpec.NEW_HOPE_1024)
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

    private static int[][] loadTable(String name, NewHopeSpec spec) {
        Module module = Ntt.class.getModule();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(module.getResourceAsStream(name)))) {
            int[][] table = reader.lines()
                    .map(line -> line.split(","))
                    .peek(items -> {
                        if (items.length != spec.n) {
                            throw new RuntimeException("Resource is corrupted");
                        }
                    })
                    .map(items -> Arrays.stream(items)
                            .map(Integer::parseInt)
                            .mapToInt(Integer::intValue)
                            .toArray()
                    )
                    .toArray(int[][]::new);
            if (table.length != spec.n) {
                throw new RuntimeException("Resource is corrupted");
            }
            return table;
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    // For NTT coefficients pre-computation

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
            System.out.println("i=" + i);
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
            System.out.println("i=" + i);
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
