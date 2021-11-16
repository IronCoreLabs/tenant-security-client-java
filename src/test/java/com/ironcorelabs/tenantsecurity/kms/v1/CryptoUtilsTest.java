package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.IntStream;
import org.testng.annotations.Test;

@Test(groups = { "unit" })
public class CryptoUtilsTest {

    // Truly random, uses the underlying OS to decide what RNG you get.
    SecureRandom secureRandom = new SecureRandom();
    DocumentMetadata metadata = new DocumentMetadata("tenantId", "requestingUserOrServiceId", "dataLabel");

    // Get a RNG that will give back the same bytes each time. By default the new
    // SecureRandom(seed) does not work like you would expect on linux. It instead
    // uses Native, which uses /dev/urandom and ignores the passed in seed.
    private SecureRandom getSecureRandom(String seed) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
        sr.setSeed(seed.getBytes("UTF-8"));
        return sr;
    }

    public static byte[] toByteArray(IntStream stream) {
        return stream.collect(ByteArrayOutputStream::new, (baos, i) -> baos.write((byte) i),
                (baos1, baos2) -> baos1.write(baos2.toByteArray(), 0, baos2.size())).toByteArray();
    }

    // Converts a hex string to a byte array. The hex string must be an even number
    // of characters.
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException(s + " is not a string with an even number of characters.");
        }
        byte[] result = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            result[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return result;
    }

    // WARNING: This method side effects the buffer that's passed in by advancing
    // it.
    public static byte[] getBytesFromBuffer(ByteBuffer buffer, int num) throws Exception {
        if (num < 0) {
            throw new IllegalArgumentException("Can't get negative bytes from buffer.");
        }
        byte[] output = new byte[num];
        buffer.get(output);
        return output;
    }

    public void generateHeaderShouldProduceKnownResult() throws Exception {
        SecureRandom localSecureRandom = getSecureRandom("the one and only seed");
        byte[] documentKey = toByteArray(IntStream.range(0, 32));
        ByteBuffer result = ByteBuffer.wrap(CryptoUtils.generateHeader(documentKey, metadata, localSecureRandom).get());
        byte[] expectedLength = { (byte) 0, (byte) 42 };
        byte[] expectedHeaderProtoBytes = { 10, 28, 49, 113, -17, 60, -119, -97, -121, 94, 89, 92, 34, 19, -54, -49,
                -110, -121, -57, -116, -15, -106, 69, -116, -42, -112, 84, 73, -128, -57, 26, 10, 10, 8, 116, 101, 110,
                97, 110, 116, 73, 100 };

        assertEquals(result.get(), (byte) 3);
        assertEquals(getBytesFromBuffer(result, 4), CryptoUtils.DOCUMENT_MAGIC);
        assertEquals(getBytesFromBuffer(result, 2), expectedLength);
        assertEquals(getBytesFromBuffer(result, 42), expectedHeaderProtoBytes);
        assertEquals(result.remaining(), 0);
    }

    public void verifyHeaderProtoShouldRoundtripWithCreateHeaderProto() throws Exception {
        byte[] documentKey = toByteArray(IntStream.range(0, 32));
        DocumentMetadata metadata = new DocumentMetadata(
                "tenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantId",
                "requestingUserOrServiceId", "dataLabel");
        assert (CryptoUtils.verifyHeaderProto(documentKey,
                CryptoUtils.createHeaderProto(documentKey, metadata, secureRandom).get()).get());
    }

    public void getHeaderFromStreamShouldWorkForGenerateHeader() throws Exception {
        SecureRandom localSecureRandom = getSecureRandom("tommy b");
        byte[] documentKey = toByteArray(IntStream.range(0, 32));
        DocumentMetadata metadata = new DocumentMetadata(
                "tenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantIdtenantId",
                "requestingUserOrServiceId", "dataLabel");
        byte[] header = CryptoUtils.generateHeader(documentKey, metadata, localSecureRandom).get();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(header);
        // The test is just that it works to get the header from the stream.
        CryptoUtils.getHeaderFromStream(inputStream).get();
    }

    public void streamingEncryptDecryptTest() throws Exception {
        byte[] documentKey = new byte[32];
        secureRandom.nextBytes(documentKey);
        byte[] plaintext = new byte[2000];
        secureRandom.nextBytes(plaintext);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream encryptOutputStream = new ByteArrayOutputStream();
        CryptoUtils.encryptStreamInternal(documentKey, metadata, inputStream, encryptOutputStream, secureRandom).get();
        byte[] encryptedBytes = encryptOutputStream.toByteArray();
        ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
        ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encryptedBytes);
        CryptoUtils.decryptStreamInternal(documentKey, encryptedStream, decryptedStream).get();
        assertEquals(decryptedStream.toByteArray(), plaintext);
    }

    public void encryptWithStreamingDecryptTest() throws Exception {
        byte[] documentKey = new byte[32];
        secureRandom.nextBytes(documentKey);
        byte[] plaintext = new byte[244];
        secureRandom.nextBytes(plaintext);
        byte[] encryptedBytes = CryptoUtils.encryptBytes(plaintext, metadata, documentKey, secureRandom).get();
        ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
        ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encryptedBytes);
        CryptoUtils.decryptStreamInternal(documentKey, encryptedStream, decryptedStream).get();
        assertEquals(decryptedStream.toByteArray(), plaintext);
    }

    public void streamingEncryptWithNormalDecrypt() throws Exception {
        byte[] documentKey = new byte[32];
        secureRandom.nextBytes(documentKey);
        byte[] plaintext = new byte[112];
        secureRandom.nextBytes(plaintext);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream encryptOutputStream = new ByteArrayOutputStream();
        CryptoUtils.encryptStreamInternal(documentKey, metadata, inputStream, encryptOutputStream, secureRandom).get();
        byte[] encryptedBytes = encryptOutputStream.toByteArray();
        byte[] decryptedBytes = CryptoUtils.decryptDocument(encryptedBytes, documentKey).get();
        assertEquals(decryptedBytes, plaintext);
    }

    // This test is a value that shows decryption of a value created in using the
    // php sdk.
    public void decryptLargeDocumentFromPHPTests() throws Exception {
        byte[] encryptedDocument = hexStringToByteArray(
                "0349524f4e016c0a1c3130eaf8ff88c1a08df550095522aebfdc7b0d060d3adad8836fea7e1acb020ac80274656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e74496474656e616e744964bb54218111033f5c68c92feb8fae88c255cc56e902becdfde679defa2628950beb966e0e43d27f42dcdbd98587e8bf5f8458411760fb72ca4442ae79877da90dff7de6df43e549df3085aae5f55f05aa37cdd045ffa7");
        byte[] dek = hexStringToByteArray("3939393939393939393939393939393939393939393939393939393939393939");
        byte[] result = CryptoUtils.decryptDocument(encryptedDocument, dek).get();
        String resultString = new String(result); // These bytes were utf-8 bytes so we just load them into a string for
                                                  // our assertion.
        assertEquals(resultString, "I have a fever and the only cure is nine nine nine nine...");
    }

    public void verifyV3DocWithZeroSize() throws Exception {
        byte[] edoc = new byte[] { 3, 73, 82, 79, 78, 0, 0, 52, 97, 69, -17, -65, 32, 85, -70, 101, 109, -67, 31, -28,
                -38, -19, -78, 42, 125, 124, -47, 80, 31, 10, 127, -109, -20, 90, 7, 88, 104, 103, -64, -56, 38, 95, 96,
                -97, -92, -54 };
        ByteArrayInputStream edoc_stream = new ByteArrayInputStream(edoc);
        boolean isHeaderValid = CryptoUtils.getHeaderFromStream(edoc_stream)
                .thenCompose(header -> CryptoUtils.verifyHeaderProto(new byte[0], header)).get();
        assert (isHeaderValid);
    }

    public void streamingEncryptWithNormalDecrypt60bytes() throws Exception {
        byte[] documentKey = new byte[32];
        secureRandom.nextBytes(documentKey);
        byte[] plaintext = new byte[60];
        secureRandom.nextBytes(plaintext);
        ByteArrayInputStream inputStream = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream encryptOutputStream = new ByteArrayOutputStream();
        CryptoUtils.encryptStreamInternal(documentKey, metadata, inputStream, encryptOutputStream, secureRandom).get();
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
        CryptoUtils.encryptStreamInternal(documentKey, metadata, inputStream, encryptOutputStream, secureRandom).get();
        byte[] encryptedBytes = encryptOutputStream.toByteArray();
        byte[] messedUpEncyptedBytes = Arrays.copyOf(encryptedBytes, length);
        messedUpEncyptedBytes[length - 1] = 0;
        messedUpEncyptedBytes[length - 2] = 0; // making the last 2 bytes 0 means the tag should be messed up so the
                                               // decrypt should fail.
        CryptoUtils.decryptDocument(messedUpEncyptedBytes, documentKey).get();
    }

    public void streamingEncryptWithNormalDecryptLargeDocument() throws Exception {
        // 30 seconds
        long cutoffMillis = 30 * 1000;
        SecureRandom sha1SecureRandom = getSecureRandom("some seed");
        byte[] documentKey = new byte[32];
        sha1SecureRandom.nextBytes(documentKey);
        // 64MB
        byte[] plaintext = new byte[64 * 1024 * 1024];
        sha1SecureRandom.nextBytes(plaintext);
        long startTime = System.currentTimeMillis();
        ByteArrayInputStream inputStream = new ByteArrayInputStream(plaintext);
        ByteArrayOutputStream encryptOutputStream = new ByteArrayOutputStream();
        CryptoUtils.encryptStreamInternal(documentKey, metadata, inputStream, encryptOutputStream, secureRandom).get();
        byte[] encryptedBytes = encryptOutputStream.toByteArray();
        byte[] decryptedBytes = CryptoUtils.decryptDocument(encryptedBytes, documentKey).get();
        long timeTaken = System.currentTimeMillis() - startTime;
        if (timeTaken > cutoffMillis) {
            throw new Exception(
                    "Decrypting " + plaintext.length + " took " + timeTaken + ". It shouldn't take that long.");
        }
        assertEquals(decryptedBytes, plaintext);
    }

    public void getNBytesHappy() throws Exception {
        byte[] buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        byte[] expected = { 1 };
        assertEquals(CryptoUtils.readNBytes(new ByteArrayInputStream(buffer), 1), expected);
    }

    public void getNBytesRequestMore() throws Exception {
        byte[] buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        assertEquals(CryptoUtils.readNBytes(new ByteArrayInputStream(buffer), 11), buffer);
    }

    public void getNBytesRequestEmpty() throws Exception {
        byte[] buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        assertEquals(CryptoUtils.readNBytes(new ByteArrayInputStream(buffer), 0), new byte[0]);
    }

    @Test(expectedExceptions = IllegalArgumentException.class, expectedExceptionsMessageRegExp = ".*length.*")
    public void getNBytesNegativelen() throws Exception {
        byte[] buffer = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        CryptoUtils.readNBytes(new ByteArrayInputStream(buffer), -1);
    }

    public void getNBytesRequestMoreOnEmpty() throws Exception {
        byte[] buffer = new byte[0];
        assertEquals(CryptoUtils.readNBytes(new ByteArrayInputStream(buffer), 10), new byte[0]);
    }
}
