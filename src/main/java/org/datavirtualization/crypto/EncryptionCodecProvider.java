
package org.datavirtualization.crypto;

import org.datavirtualization.config.CryptographyConfig;
import org.datavirtualization.util.CryptographyUtil;

/**
 * <p>
 * Allows implementation of encrypt/decrypt/compare for custom schemes as needed
 * for various cryptography things. It is not required for all providers
 * to implement all methods of the interface. Asymmetry is possible especially
 * in cases where encryption is one way. Asymmetric interfaces should return
 * {@link UnsupportedOperationException} where appropriate.
 * </p>
 * 
 * <p>
 * See {@link CryptographyUtil} for raw access to encryption methods without a
 * provider.
 * </p>
 * 
 * @see CryptographyUtil
 */
public interface EncryptionCodecProvider {
    /**
     * Encrypt the given cleartext using the implementation of this provider.
     * 
     * @param cleartext
     *            The unencrypted plaintext.
     * @return The ciphertext representing the given cleartext.
     */
    String encrypt(final String cleartext);

    /**
     * Decrypt the given ciphertext using the implementation of this provider.
     * 
     * @param ciphertext
     *            A string which was previously encrypted using the same
     *            algorithm represented by this implementation.
     * @return The decrypted cleartext. Passing in a string encrypted through
     *         some other algorithm will produce gibberish as output.
     */
    String decrypt(final String ciphertext);

    /**
     * This shortcut method saves you the hassle of doing the comparison
     * directly. Calling this method can be considered the equivalent of either
     * <ul>
     * <li>codec.decrypt(ciphertext).equals(cleartext)</li>
     * <li>codec.encrypt(cleartext).equals(ciphertext)</li>
     * </ul>
     * which must always give the same result.
     * 
     * @param cleartext
     *            Unencrypted text.
     * @param ciphertext
     *            Encrypted text.
     * @return True if the encryption matches up as described above, false
     *         otherwise.
     */
    boolean compare(final String cleartext, final String ciphertext);

    /**
     * Tests whether the text provided is a cipher text. Throws a
     * {@link RuntimeException} if the text is a clear text.
     * 
     * @param text
     *            any text to test
     */
    void assertCipherText(final String text);
}
