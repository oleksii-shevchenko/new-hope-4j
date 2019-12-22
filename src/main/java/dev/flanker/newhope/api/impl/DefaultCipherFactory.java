package dev.flanker.newhope.api.impl;

import dev.flanker.newhope.api.Cipher;
import dev.flanker.newhope.api.CipherFactory;
import dev.flanker.newhope.api.domain.CipherIdentifier;
import dev.flanker.newhope.chiper.NewHopeCipher;
import dev.flanker.newhope.spec.NewHopeSpec;

import java.security.SecureRandom;
import java.util.Map;
import java.util.function.Supplier;

public class DefaultCipherFactory implements CipherFactory {
    private static volatile DefaultCipherFactory INSTANCE;

    private final Map<CipherIdentifier, Supplier<Cipher>> suppliers = Map.of(
            CipherIdentifier.NEW_HOPE_512, () -> new NewHopeCipher(new SecureRandom(), NewHopeSpec.NEW_HOPE_512),
            CipherIdentifier.NEW_HOPE_1024, () -> new NewHopeCipher(new SecureRandom(), NewHopeSpec.NEW_HOPE_1024)
    );

    private DefaultCipherFactory() { }

    @Override
    public Cipher get(String cipherId) {
        return get(CipherIdentifier.valueOf(cipherId.toUpperCase()));
    }

    @Override
    public Cipher get(CipherIdentifier id) {
        Supplier<Cipher> cipherSupplier = suppliers.get(id);
        if (cipherSupplier != null) {
            return cipherSupplier.get();
        } else {
            throw new IllegalArgumentException("Unsupported cipher");
        }
    }

    public static DefaultCipherFactory getInstance() {
        if (INSTANCE == null) {
            synchronized (DefaultCipherFactory.class) {
                if (INSTANCE == null) {
                    INSTANCE = new DefaultCipherFactory();
                }
            }
        }
        return INSTANCE;
    }
}
