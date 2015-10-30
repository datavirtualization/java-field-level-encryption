package org.datavirtualization.util;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Throwables;
import com.google.common.io.BaseEncoding;
import org.datavirtualization.config.CryptographyConfig;
import org.datavirtualization.crypto.AesCodecProvider;
import org.datavirtualization.crypto.EncryptionCodecProvider;
import org.datavirtualization.crypto.PassthroughCodecProvider;

/**
 * Contains functions for assisting in cryptography tasks such as SHA-1 checks.
 * 
 * @author bvesco, Nov 13, 2009
 */
public final class CryptographyUtil {
    public static final EncryptionCodecProvider piiCodec          = CryptographyConfig.PII_SECRET == null ? new PassthroughCodecProvider() : new AesCodecProvider(CryptographyConfig.PII_SECRET);

    private static final Logger                 logger            = LoggerFactory.getLogger(CryptographyUtil.class);

    public static final String                  ALGORITHM_SHA_1   = "HmacSHA1";
    public static final String                  ALGORITHM_SHA_256 = "HmacSHA256";
    public static final String                  ALGORITHM_AES     = "AES";

    /**
     * Computes an HMAC hash.
     * 
     * @param algorithm
     *            The HMAC algorithm.
     * @param secret
     *            The secret.
     * @param plainText
     *            The plain text to be hashed.
     * @return The hash, in bytes.
     */
    public static byte[] computeHmacHash(String algorithm, String secret, String... plainText) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            // todo: secret is weak: switch to be hex encoding: https://trello.com/c/lXasud5g/1381-secret-key-encoding-is-weak
            mac.init(new SecretKeySpec(secret.getBytes(CryptographyConfig.APP_CHARSET), mac.getAlgorithm()));

            for (String value : plainText)
            {
                mac.update(value.getBytes(CryptographyConfig.APP_CHARSET));
            }

            byte[] result = mac.doFinal();
            return result;
        }
        catch (NoSuchAlgorithmException e) {
            logger.error("unable to compute hash due to missing encryption algorithm", e);
        }
        catch (InvalidKeyException e) {
            logger.error("Invalid Key, unable to compute hash", e);
        }
        return null;
    }

    /**
     * Compare passwords using an MD5 encryption algorithm.
     * 
     * @param salt
     *            The encryption salt token, may be passed as the empty string
     *            if you are not using salt.
     * @param password
     *            The clear text password being checked.
     * @param expected
     *            The encrypted string to check against.
     * @return True if encrypting salt+password is equal to expected, false
     *         otherwise.
     */
    public static boolean comparePasswordsMd5(String salt, String password, String expected) {
        try {
            MessageDigest md5Digest = MessageDigest.getInstance("MD5");

            String toEncrypt = salt + password;

            // todo: secret is weak: switch to be hex encoding: https://trello.com/c/lXasud5g/1381-secret-key-encoding-is-weak
            md5Digest.update(toEncrypt.getBytes(CryptographyConfig.APP_CHARSET), 0, toEncrypt.length());

            return checkHash(md5Digest.digest(), expected);
        }
        catch (NoSuchAlgorithmException e) {
            throw Throwables.propagate(e);
        }
    }

    /**
     * Generate an MD5 hash of the given string.
     * 
     * @param value
     *            The string to be encrypted.
     * @return A hex encoded string representing the MD5 encoded input.
     */
    public static String md5(String value) {
        try {
            MessageDigest md5Digest = MessageDigest.getInstance("MD5");

            md5Digest.update(value.getBytes(CryptographyConfig.APP_CHARSET), 0, value.length());

            return Hex.encodeHexString(md5Digest.digest());
        }
        catch (NoSuchAlgorithmException e) {
            throw Throwables.propagate(e);
        }
    }

    /**
     * Generate a SHA-256 hash of the given string.
     * 
     * @param value
     *            The string to be encrypted.
     * @return A hex encoded string representing the SHA-256 encoded input.
     */
    public static String sha256(String value)  {
        return sha256(value, CryptographyConfig.APP_SECRET);
    }

    /**
     * Generate a SHA-256 hash of the given string.
     * 
     * @param value
     *            The string to be encrypted.
     * @return A hex encoded string representing the SHA-256 encoded input.
     */
    public static String sha256(String value, String secret) {
        byte[] hash = computeHmacHash(ALGORITHM_SHA_256, secret, value);
        String hashString = Hex.encodeHexString(hash);

        return hashString;
    }

    /**
     * @return base16 / Hex encoded key for AES-128 encryption.
     */
    public static String generateAes128Key()  {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
            keyGenerator.init(128);
            final SecretKey secretKey = keyGenerator.generateKey();

            return BaseEncoding.base16().encode(secretKey.getEncoded());
        }
        catch (NoSuchAlgorithmException e)  {
            throw new RuntimeException("No support for AES encryption provided by the platform", e);
        }
    }

    /**
     * @return base16 / Hex encoded key for AES-256 encryption.
     */
    public static String generateAes256Key()  {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM_AES);
            keyGenerator.init(256);
            final SecretKey secretKey = keyGenerator.generateKey();

            return BaseEncoding.base16().encode(secretKey.getEncoded());
        }
        catch (NoSuchAlgorithmException e)  {
            throw new RuntimeException("No support for AES encryption provided by the platform", e);
        }
    }

    /**
     * Checks for equality of {@code hash} and {@code authToken}.
     * 
     * @param hash
     *            The hash, in bytes.
     * @param authToken
     *            The raw auth token.
     * @return True, if {@code hash} and {@code authToken} are considered to be
     *         equal.
     */
    private static boolean checkHash(byte[] hash, String authToken) {
        byte[] hex;
        try {
            hex = Hex.decodeHex(authToken.toCharArray());
        }
        catch (DecoderException e)  {
            return false;
        }
        return Arrays.equals(hash, hex);
    }

    /** Non-instantiable */
    private CryptographyUtil() {}
}
