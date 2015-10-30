package org.datavirtualization.crypto;

/**
 * Does not do any encryption at all. Essentially a pass-through implementation.
 * 
 */
public class PassthroughCodecProvider implements EncryptionCodecProvider {
    @Override
    public String encrypt(String cleartext) {
        return cleartext;
    }

    @Override
    public String decrypt(String ciphertext) {
        return ciphertext;
    }

    @Override
    public boolean compare(String cleartext, String ciphertext) {
        return cleartext.equals(ciphertext);
    }

    @Override
    public void assertCipherText(String text) {}
}