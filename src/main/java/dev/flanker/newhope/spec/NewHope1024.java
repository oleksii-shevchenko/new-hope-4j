package dev.flanker.newhope.spec;

@SuppressWarnings("FieldCanBeLocal")
public class NewHope1024 implements NewHopeSpec {
    private static int N = 1024;
    private static int LOG_N = 10;

    private static int Q = 12289;
    private static int K = 8;
    private static int G = 7;
    private static int W = 49;

    private static int INV_G = 8778;
    private static int INV_W = 1254;
    private static int INV_N = 12277;

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
}
