package com.ironcorelabs.tenantsecurity.utils;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.testng.annotations.Test;

@Test(groups = { "unit" })
public class CryptoUtilsTest {
    SecureRandom secureRandom = new SecureRandom(new byte[10]);

    public void decryptStreamingTest() throws Exception {
        byte[] documentKey = new byte[32];
        secureRandom.nextBytes(documentKey);
        byte[] plaintext = new byte[2000];
        ByteArrayInputStream inputStream = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream encryptOutputStream = new ByteArrayOutputStream();
        CryptoUtils.encryptStreamInternal(documentKey, inputStream, encryptOutputStream, secureRandom).get();
        byte[] encryptedBytes = encryptOutputStream.toByteArray();
        ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
        ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encryptedBytes);
        CryptoUtils.decryptStreamInternal(documentKey, encryptedStream, decryptedStream).get();
        assertEquals(decryptedStream.toByteArray(), plaintext);
    }
}
