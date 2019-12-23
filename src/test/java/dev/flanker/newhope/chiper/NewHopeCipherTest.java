package dev.flanker.newhope.chiper;

import dev.flanker.newhope.api.domain.KeyPair;
import dev.flanker.newhope.spec.NewHopeSpec;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class NewHopeCipherTest {
    @Test
    public void consistencyTest() {
        NewHopeCipher cipher = new NewHopeCipher(new SecureRandom(), NewHopeSpec.NEW_HOPE_512);
        KeyPair keyPair = cipher.generateKeyPair();
        cipher.dualMode(keyPair);

        byte[] b = new byte[32];
        ThreadLocalRandom.current().nextBytes(b);

        byte[] encrypt = cipher.encrypt(b);
        byte[] decrypt = cipher.decrypt(encrypt);

        System.out.println(Arrays.toString(b));
        System.out.println(Arrays.toString(decrypt));

        assertArrayEquals(b, decrypt);
    }

}