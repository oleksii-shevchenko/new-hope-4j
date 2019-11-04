package dev.flanker.newhope.spec;

@SuppressWarnings("FieldCanBeLocal")
public final class NewHope1024 implements NewHopeSpec {
    private static final NewHope1024 INSTANCE = new NewHope1024();

    private static final int N = 1024;
    private static final int LOG_N = 10;

    private static final int Q = 12289;
    private static final int K = 8;
    private static final int G = 7;
    private static final int W = 49;

    private static final int INV_G = 8778;
    private static final int INV_W = 1254;
    private static final int INV_N = 12277;

    private NewHope1024() { }

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

    public static NewHope1024 getInstance() {
        return INSTANCE;
    }
}
