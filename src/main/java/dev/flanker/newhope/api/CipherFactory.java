package dev.flanker.newhope.api;

public interface CipherFactory {
    Cipher create(NewHopeVersion version);

    Cipher create(NewHopeVersion version, byte[] seed);
}
