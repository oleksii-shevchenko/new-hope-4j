package dev.flanker.newhope.spec;

public interface NewHopeSpec {
    int Q = 12289;
    int K = 8;

    int n();
    int logN();

    int gamma();
    int w();

    int invW();
    int invGamma();
    int invN();

    default int q() {
        return Q;
    }

    default  int k() {
        return K;
    }
}
