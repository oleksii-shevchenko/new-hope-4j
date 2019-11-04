package dev.flanker.newhope.spec;

public final class NewHope512 implements NewHopeSpec {
    private static final NewHope512 INSTANCE = new NewHope512();

    private static final int N = 512;
    private static final int LOG_N = 9;

    private static final int Q = 12289;
    private static final int K = 8;
    private static final int G = 10968;
    private static final int W = 3;

    private static final int INV_G = 3656;
    private static final int INV_W = 8193;
    private static final int INV_N = 12265;

    private NewHope512() { }

    @Override
    public int n() {
        return N;
    }

    @Override
    public int logN() {
        return LOG_N;
    }

    @Override
    public int q() {
        return Q;
    }

    @Override
    public int k() {
        return K;
    }

    @Override
    public int gamma() {
        return G;
    }

    @Override
    public int w() {
        return W;
    }

    @Override
    public int invW() {
        return INV_W;
    }

    @Override
    public int invGamma() {
        return INV_G;
    }

    @Override
    public int invN() {
        return INV_N;
    }

    public static NewHope512 getInstance() {
        return INSTANCE;
    }
}
