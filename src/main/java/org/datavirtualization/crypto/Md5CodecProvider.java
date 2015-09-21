package org.datavirtualization.crypto;

import org.datavirtualization.util.CryptographyUtil;

/**
 * Codec provider based on the MD5 encryption algorithm.
 */
public class Md5CodecProvider implements EncryptionCodecProvider {
    @Override
    public String encrypt(final String cleartext) {
        return CryptographyUtil.md5(cleartext);
    }

    /**
     * This method throws {@link UnsupportedOperationException} since MD5 is a
     * one way operation.
     */
    @Override
    public String decrypt(final String ciphertext) {
        throw new UnsupportedOperationException("No decrypting with MD5");
    }

    @Override
    public boolean compare(final String cleartext, final String ciphertext) {
        return ciphertext.equals(encrypt(cleartext));
    }

    @Override
    public void assertCipherText(String text) {
        throw new UnsupportedOperationException("No decrypting with MD5");
    }
}
