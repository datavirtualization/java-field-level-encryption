package org.datavirtualization.crypto.test;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import org.datavirtualization.util.CryptographyUtil;

/**
 * An admin command to generate a AES-128 Keys.
 */
public class GenerateAes128KeyCommandTest {
   @Test
    public void batch() throws Exception {
		CryptographyUtil.generateAes128Key();
    }
}
