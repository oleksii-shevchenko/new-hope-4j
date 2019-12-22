package dev.flanker.newhope.chiper;

import dev.flanker.newhope.api.KeyFactory;
import dev.flanker.newhope.api.PrivateKey;
import dev.flanker.newhope.api.PublicKey;
import dev.flanker.newhope.chiper.domain.NewHopePrivateKey;
import dev.flanker.newhope.chiper.domain.NewHopePublicKey;
import dev.flanker.newhope.internal.Encoder;
import dev.flanker.newhope.spec.NewHopeSpec;

import java.util.Map;

public class NewHopeKeyFactory implements KeyFactory {
    private static Map<NewHopeSpec, NewHopeKeyFactory> KEY_FACTORY = Map.of(
            NewHopeSpec.NEW_HOPE_512, new NewHopeKeyFactory(NewHopeSpec.NEW_HOPE_512),
            NewHopeSpec.NEW_HOPE_1024, new NewHopeKeyFactory(NewHopeSpec.NEW_HOPE_1024)
    );

    private final NewHopeSpec spec;

    private NewHopeKeyFactory(NewHopeSpec spec) {
        this.spec = spec;
    }

    @Override
    public NewHopePublicKey decodePublicKey(byte[] encoded) {
        return Encoder.decodePublicKey(encoded, spec);
    }

    @Override
    public NewHopePrivateKey decodePrivateKey(byte[] encoded) {
        return new NewHopePrivateKey(Encoder.decodePolynomial(encoded, spec));
    }

    public static NewHopeKeyFactory getInstance(NewHopeSpec spec) {
        NewHopeKeyFactory newHopeKeyFactory = KEY_FACTORY.get(spec);
        if (newHopeKeyFactory != null) {
            return newHopeKeyFactory;
        } else {
            throw new RuntimeException("Unsupported specification");
        }
    }

    @Override
    public byte[] encodePrivateKey(PrivateKey privateKey) {
        assert privateKey != null;
        assert privateKey instanceof NewHopePrivateKey;

        NewHopePrivateKey key = (NewHopePrivateKey) privateKey;
        assert key.s() != null;

        return Encoder.encodePolynomial(key.s(), spec);
    }

    @Override
    public byte[] encodePublicKey(PublicKey publicKey) {
        assert publicKey != null;
        assert publicKey instanceof NewHopePublicKey;

        NewHopePublicKey key = (NewHopePublicKey) publicKey;
        assert key.b() != null;
        assert key.publicSeed() != null;

        return Encoder.encodePublicKey(key, spec);
    }
}
