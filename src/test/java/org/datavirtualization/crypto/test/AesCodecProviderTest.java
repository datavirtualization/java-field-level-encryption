package org.datavirtualization.crypto.test;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import org.datavirtualization.crypto.AesCodecProvider;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

public class AesCodecProviderTest {
    private static final String EXACT_KEY     = "00000000000000000000000000000000";
    private static final String INVALID_CHARS = "iHaveCharsNotValidInHexStringsYo";
    private static final String SHORT_KEY     = EXACT_KEY.substring(0, EXACT_KEY.length() - 1);
    private static final String LONG_KEY      = EXACT_KEY + "0";

    private static final String CANNED_KEY    = "00000000000000000000000000000000";
    private final String        CANNED_CLEAR;
    private final String        CANNED_CIPHER;

    private final String        BATCH         = "{\"commands\":[{\"action\":\"player.friendship.action\",\"args\":{\"recipientLiddleId\":{\"playerId\":\"2\",\"avatarId\":\"a1\"},\"liddleId\":{\"playerId\":\"1\",\"avatarId\":\"a1\"},\"actionKey\":\"friendshipAction.inviteOver\"},\"requestId\":8,\"time\":1316795648},{\"action\":\"player.romance.breakUp\",\"args\":{\"otherLiddleId\":{\"playerId\":\"2\",\"avatarId\":\"a1\"},\"liddleId\":{\"playerId\":\"1\",\"avatarId\":\"a1\"}},\"expectedStatus\":1098,\"requestId\":9,\"time\":1316795648},{\"action\":\"player.romance.becomeOfficial\",\"args\":{\"otherLiddleId\":{\"playerId\":\"2\",\"avatarId\":\"a1\"},\"liddleId\":{\"playerId\":\"1\",\"avatarId\":\"a1\"}},\"requestId\":10,\"time\":1316795648},{\"action\":\"player.romance.breakUp\",\"args\":{\"otherLiddleId\":{\"playerId\":\"2\",\"avatarId\":\"a1\"},\"liddleId\":{\"playerId\":\"1\",\"avatarId\":\"a1\"}},\"requestId\":11,\"time\":1316795648},{\"action\":\"player.romance.breakUp\",\"args\":{\"otherLiddleId\":{\"playerId\":\"2\",\"avatarId\":\"a1\"},\"liddleId\":{\"playerId\":\"1\",\"avatarId\":\"a1\"}},\"requestId\":12,\"time\":1316795648},{\"action\":\"player.friendship.action\",\"args\":{\"recipientLiddleId\":{\"playerId\":\"2\",\"avatarId\":\"a1\"},\"liddleId\":{\"playerId\":\"1\",\"avatarId\":\"a1\"},\"actionKey\":\"friendshipAction.inviteOver\"},\"requestId\":13,\"time\":1316795648}],\"authKey\":\"EkZN-dcY4xRffD77eOxLB-7zHWFlsK8cs_1as_2Yh3I.eyJwaWQiOiIxIiwiZXhwaXJlcyI6IjEzMTY3OTU2NDgifQ\"}";

    private String effMe(String hexChars) throws Exception {
        return new String(Hex.decodeHex(hexChars.toCharArray()));
    }

    private String effYou(String hexBytes) throws Exception {
        return new String(Hex.encodeHex(hexBytes.getBytes()));
    }

    public AesCodecProviderTest() throws Exception {
        CANNED_CLEAR = effMe("80000000000000000000000000000000");
        CANNED_CIPHER = effMe("3ad78e726c1ec02b7ebfe92b23d9ec34");
    }

    @BeforeClass
    public void keyLengths() throws Exception {
        assertEquals(EXACT_KEY.length(), 32);
        assertTrue(SHORT_KEY.length() < EXACT_KEY.length());
        assertTrue(LONG_KEY.length() > EXACT_KEY.length());

        assertEquals(CANNED_KEY.length(), EXACT_KEY.length());
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void shortKey() throws Exception {
        final AesCodecProvider codec = new AesCodecProvider();
        codec.setPasswordKey(SHORT_KEY);
    }

    @Test(expectedExceptions = DecoderException.class)
    public void invalidCharsInKey() throws Exception {
        final AesCodecProvider codec = new AesCodecProvider();
        codec.setPasswordKey(INVALID_CHARS);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void longKey() throws Exception {
        final AesCodecProvider codec = new AesCodecProvider();
        codec.setPasswordKey(LONG_KEY);
    }

    @Test(expectedExceptions = IllegalStateException.class)
    public void changeKey() throws Exception {
        final AesCodecProvider codec = new AesCodecProvider();
        codec.setPasswordKey(EXACT_KEY);
        codec.setPasswordKey(EXACT_KEY);
    }

    /** Not sure what valid values I can jam in here to verify */
    public void cannedEncrypt() throws Exception {
        final AesCodecProvider codec = new AesCodecProvider();
        codec.setPasswordKey(CANNED_KEY);
        final String cipher = codec.encrypt(CANNED_CLEAR);
        System.err.println(cipher);
        System.err.println(CANNED_CIPHER);
        System.err.println(effYou(cipher));
        System.err.println(effYou(CANNED_CIPHER));
        assertEquals(cipher, CANNED_CIPHER);
    }

    /** Not sure what valid values I can jam in here to verify */
    public void cannedDecrypt() throws Exception {
        final AesCodecProvider codec = new AesCodecProvider();
        codec.setPasswordKey(CANNED_KEY);
        final String clear = codec.decrypt(CANNED_CIPHER);
        assertEquals(clear, CANNED_CLEAR);
    }

    @Test
    public void twoWay() throws Exception {
        final AesCodecProvider codec = new AesCodecProvider();
        codec.setPasswordKey(EXACT_KEY);
        final String cipher = codec.encrypt(CANNED_CLEAR);
        final String clear = codec.decrypt(cipher);
        assertEquals(clear, CANNED_CLEAR);
    }

    @Test
    public void batch() throws Exception {
        final AesCodecProvider codec = new AesCodecProvider();
        codec.setPasswordKey(EXACT_KEY);
        final String cipher = codec.encrypt(BATCH);
        final String clear = codec.decrypt(cipher);
        assertEquals(clear, BATCH);
    }
}
