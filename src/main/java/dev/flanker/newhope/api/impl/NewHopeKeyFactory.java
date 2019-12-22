package dev.flanker.newhope.api.impl;

import dev.flanker.newhope.api.KeyFactory;
import dev.flanker.newhope.api.PrivateKey;
import dev.flanker.newhope.api.PublicKey;
import dev.flanker.newhope.chiper.NewHopePrivateKey;
import dev.flanker.newhope.internal.Encoder;

public final class NewHopeKeyFactory implements KeyFactory {
    private static final NewHopeKeyFactory INSTANCE = new NewHopeKeyFactory();

    private NewHopeKeyFactory() { }

    @Override
    public PublicKey publicKey(byte[] encoded) {
        return Encoder.decodePublicKey(encoded, Encoder.resolvePublicKeyN(encoded));
    }

    @Override
    public PrivateKey privateKey(byte[] encoded) {
        return new NewHopePrivateKey(Encoder.decodePolynomial(encoded, Encoder.resolvePolyLength(encoded)));
    }

    public static NewHopeKeyFactory getInstance() {
        return INSTANCE;
    }
}
