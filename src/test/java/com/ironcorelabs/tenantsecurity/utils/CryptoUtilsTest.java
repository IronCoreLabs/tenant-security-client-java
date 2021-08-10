package com.ironcorelabs.tenantsecurity.utils;

import static org.testng.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import org.testng.annotations.Test;

@Test(groups = { "unit" })
public class CryptoUtilsTest {
    SecureRandom secureRandom = new SecureRandom(new byte[10]);

    public void streamingEncryptDecryptTest() throws Exception {
        byte[] documentKey = new byte[32];
        secureRandom.nextBytes(documentKey);
        byte[] plaintext = new byte[2000];
        secureRandom.nextBytes(plaintext);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream encryptOutputStream = new ByteArrayOutputStream();
        CryptoUtils.encryptStreamInternal(documentKey, inputStream, encryptOutputStream, secureRandom).get();
        byte[] encryptedBytes = encryptOutputStream.toByteArray();
        ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
        ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encryptedBytes);
        CryptoUtils.decryptStreamInternal(documentKey, encryptedStream, decryptedStream).get();
        assertEquals(decryptedStream.toByteArray(), plaintext);
    }

    public void encryptWithStreamingDecryptTest() throws Exception {
        byte[] documentKey = new byte[32];
        secureRandom.nextBytes(documentKey);
        byte[] plaintext = new byte[8];
        secureRandom.nextBytes(plaintext);
        byte[] encryptedBytes = CryptoUtils.encryptBytes(plaintext, documentKey, secureRandom).get();
        ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
        ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encryptedBytes);
        CryptoUtils.decryptStreamInternal(documentKey, encryptedStream, decryptedStream).get();
        assertEquals(decryptedStream.toByteArray(), plaintext);
    }

    public void streamingEncryptWithNormalDecrypt() throws Exception {
        byte[] documentKey = new byte[32];
        secureRandom.nextBytes(documentKey);
        byte[] plaintext = new byte[2000];
        secureRandom.nextBytes(plaintext);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream encryptOutputStream = new ByteArrayOutputStream();
        CryptoUtils.encryptStreamInternal(documentKey, inputStream, encryptOutputStream, secureRandom).get();
        byte[] encryptedBytes = encryptOutputStream.toByteArray();
        byte[] decryptedBytes = CryptoUtils.decryptDocument(encryptedBytes, documentKey).get();
        assertEquals(decryptedBytes, plaintext);
    }

    @Test(expectedExceptions = java.util.concurrent.ExecutionException.class, expectedExceptionsMessageRegExp = ".*Tag mismatch!.*")
    public void streamingEncryptWithNormalDecryptFailureWithBadTag() throws Exception {
        int length = 2000;
        byte[] documentKey = new byte[32];
        secureRandom.nextBytes(documentKey);
        byte[] plaintext = new byte[length];
        secureRandom.nextBytes(plaintext);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream encryptOutputStream = new ByteArrayOutputStream();
        CryptoUtils.encryptStreamInternal(documentKey, inputStream, encryptOutputStream, secureRandom).get();
        byte[] encryptedBytes = encryptOutputStream.toByteArray();
        byte[] messedUpEncyptedBytes = Arrays.copyOf(encryptedBytes, length);
        messedUpEncyptedBytes[length - 1] = 0;
        messedUpEncyptedBytes[length - 2] = 0; // making the last 2 bytes 0 means the tag should be messed up so the
                                               // decrypt should fail.
        CryptoUtils.decryptDocument(messedUpEncyptedBytes, documentKey).get();
    }
}
