package dev.flanker.newhope.api.impl;

import java.security.SecureRandom;

import dev.flanker.newhope.api.Cipher;
import dev.flanker.newhope.api.CipherFactory;
import dev.flanker.newhope.api.NewHopeVersion;
import dev.flanker.newhope.chiper.NewHopeCipher;
import dev.flanker.newhope.spec.NewHope1024;
import dev.flanker.newhope.spec.NewHope512;

public final class NewHopeCipherFactory implements CipherFactory {
    private static NewHopeCipherFactory INSTANCE = new NewHopeCipherFactory();

    private NewHopeCipherFactory() { }

    @Override
    public Cipher create(NewHopeVersion version) {
        switch (version) {
            case NEW_HOPE_512:
                return new NewHopeCipher(new SecureRandom(), NewHope512.getInstance());
            case NEW_HOPE_1024:
                return new NewHopeCipher(new SecureRandom(), NewHope1024.getInstance());
            default:
                throw new RuntimeException("Unsupported specification exception");
        }
    }

    @Override
    public Cipher create(NewHopeVersion version, byte[] seed) {
        switch (version) {
            case NEW_HOPE_512:
                return new NewHopeCipher(new SecureRandom(seed), NewHope512.getInstance());
            case NEW_HOPE_1024:
                return new NewHopeCipher(new SecureRandom(seed), NewHope1024.getInstance());
            default:
                throw new RuntimeException("Unsupported specification exception");
        }
    }

    public static NewHopeCipherFactory getInstance() {
        return INSTANCE;
    }
}
