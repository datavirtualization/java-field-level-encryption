package org.datavirtualization.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.playdom.manimal.config.ManimalConfig;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Required;

import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;
import com.playdom.manimal.util.CryptographyUtil;

/**
 * Codec provider based on the AES encryption algorithm.
 * <p/>
 * The AES encryption of this codec is for 128-bit encryption as that is the
 * only key length being considered as required for JVM implementations.
 * 
 * @see <a
 *      href="http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html">Standard&nbsp;Names</a>
 *      for list of recommended algorithms and status of requirement.
 * @see <a
 *      href="http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#AppA">Crypto&nbsp;Spec</a>
 *      for other details of java encryption.
 * 
 * @author bvesco, May 7, 2012
 */
public class AesCodecProvider implements EncryptionCodecProvider
{
    /**
     * Keys must be 32 hex characters in length since java only supports 128-bit
     * AES as a loose requirement.
     */
    private static final int    KEY_LEN     = 32;

    private static final String ALGO        = CryptographyUtil.ALGORITHM_AES;
    private static final String ENC_SPEC    = "AES/ECB/PKCS5Padding";

    private byte[]              passwordKey = null;

    /**
     * Creates an uninitialized instance of the class. Calling of
     * {@link #setPasswordKey(String)} is required before using any method of
     * the class.
     */
    public AesCodecProvider()
    {
    }

    /**
     * Creates an initialized instance of the class.
     * 
     * @param passwordKey
     *            The password to use in generating the AES encryption. Must be
     *            32 hex characters in length as noted above.
     */
    public AesCodecProvider(final String passwordKey)
    {
        try
        {
            setPasswordKey(passwordKey);
        }
        catch (DecoderException e)
        {
            throw Throwables.propagate(e);
        }
    }

    @Override
    public String encrypt(final String cleartext) throws RuntimeException
    {
        try
        {
            final Cipher aesCipher = Cipher.getInstance(ENC_SPEC);
            final SecretKey secretKey = new SecretKeySpec(passwordKey, ALGO);

            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            final byte[] cipherbytes = aesCipher.doFinal(cleartext.getBytes(ManimalConfig.APP_CHARSET));
            return Hex.encodeHexString(cipherbytes);
        }
        catch (Exception e)
        {
            throw Throwables.propagate(e);
        }
    }

    @Override
    public void assertCipherText(String text)
    {
        decrypt(text);
    }

    @Override
    public String decrypt(final String ciphertext)
    {
        try
        {
            final Cipher aesCipher = Cipher.getInstance(ENC_SPEC);
            final SecretKey secretKey = new SecretKeySpec(passwordKey, ALGO);

            aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
            final byte[] cipherbytes = aesCipher.doFinal(Hex.decodeHex(ciphertext.toCharArray()));
            return new String(cipherbytes, ManimalConfig.APP_CHARSET);
        }
        catch (Exception e)
        {
            throw new RuntimeException("unable to decipher " + ciphertext, e);
        }
    }

    @Override
    public boolean compare(final String cleartext, final String ciphertext)
    {
        return ciphertext.equals(encrypt(cleartext));
    }

    /**
     * Java only "requires" support for 128-bit AES which requires a 16 byte
     * key. 16 bytes is 32 hex digits.
     * 
     * @param passwordKey
     *            The password to use in generating the AES encryption. Must be
     *            32 hex characters in length as noted above.
     * @throws DecoderException
     *             when there's a problem with the format of your key.
     */
    @Required
    public void setPasswordKey(final String passwordKey) throws DecoderException
    {
        Preconditions.checkState(this.passwordKey == null, "The passwordKey was previously set and is not allowed to be set a second time");
        Preconditions.checkArgument(passwordKey.length() == KEY_LEN, "The passwordKey must be exactly %s bytes long but was %s bytes", KEY_LEN, passwordKey.length());

        this.passwordKey = Hex.decodeHex(passwordKey.toCharArray());
    }
}
