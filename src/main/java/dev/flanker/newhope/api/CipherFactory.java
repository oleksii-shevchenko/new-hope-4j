package dev.flanker.newhope.api;

import dev.flanker.newhope.api.domain.CipherIdentifier;
import dev.flanker.newhope.api.impl.DefaultCipherFactory;

public interface CipherFactory {
    Cipher get(String id);

    Cipher get(CipherIdentifier id);

    static CipherFactory getDefault() {
        return DefaultCipherFactory.getInstance();
    }
}
