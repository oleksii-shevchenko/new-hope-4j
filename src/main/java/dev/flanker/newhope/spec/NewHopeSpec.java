package dev.flanker.newhope.spec;

public enum NewHopeSpec {
    NEW_HOPE_512 (512, 9, 3,  10968, 8193, 3656, 12265),
    NEW_HOPE_1024(1024, 10, 49, 7, 1254, 8778, 12277);

    NewHopeSpec(int n, int logN, int w, int g, int invW, int invG, int invN) {
        this.n = n;
        this.logN = logN;
        this.w = w;
        this.g = g;
        this.invW = invW;
        this.invG = invG;
        this.invN = invN;
    }

    public final int q = 12289;
    public final int k = 8;

    public final int n;
    public final int logN;

    public final int w;
    public final int g;

    public final int invW;
    public final int invG;

    public final int invN;
}
