package dev.flanker.newhope.chiper;

import dev.flanker.newhope.api.domain.KeyPair;
import dev.flanker.newhope.spec.NewHopeSpec;
import org.junit.jupiter.api.RepeatedTest;

import java.security.SecureRandom;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class NewHopeCipherTest {
    private static final int RUNS_NUMBER = 32;

    @RepeatedTest(RUNS_NUMBER)
    public void consistencyTest() {
        NewHopeCipher cipher = new NewHopeCipher(new SecureRandom(), NewHopeSpec.NEW_HOPE_512);
        KeyPair keyPair = cipher.generateKeyPair();
        cipher.dualMode(keyPair);

        byte[] message = new byte[32];
        ThreadLocalRandom.current().nextBytes(message);

        byte[] encrypt = cipher.encrypt(message);
        byte[] decrypt = cipher.decrypt(encrypt);

        assertArrayEquals(message, decrypt);
    }
}