package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.testng.annotations.Test;

@Test(groups = { "dev-integration" })
public class KMSClientTest {
    private String GCP_TENANT_ID = "INTEGRATION-TEST-DEV1-GCP";
    private String AWS_TENANT_ID = "INTEGRATION-TEST-DEV1-AWS";
    private String AZURE_TENANT_ID = "INTEGRATION-TEST-DEV1-AZURE";
    private String INTEGRATION_API_KEY = "qlhqGW+Azctfy1ld";

    @Test(expectedExceptions = java.net.MalformedURLException.class)
    public void constructorUrlTest() throws Exception {
        new TenantSecurityKMSClient("foobaz", "apiKey");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void missingApiKeyTest() throws Exception {
        new TenantSecurityKMSClient("http://localhost", null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void emptyApiKeyTest() throws Exception {
        new TenantSecurityKMSClient("http://localhost", "");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void invalidRequestThreadpoolSize() throws Exception {
        new TenantSecurityKMSClient("http://localhost", "apiKey", 0, 1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void invalidCryptoThreadpoolSize() throws Exception {
        new TenantSecurityKMSClient("http://localhost", "apiKey", 1, 0);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void missingRandomGen() throws Exception {
        new TenantSecurityKMSClient("http://localhost", "apiKey",
                TenantSecurityKMSClient.DEFAULT_REQUEST_THREADPOOL_SIZE,
                TenantSecurityKMSClient.DEFAULT_AES_THREADPOOL_SIZE, null);
    }

    private void assertEqualBytes(byte[] one, byte[] two) throws Exception {
        assertEquals(new String(one, "UTF-8"), new String(two, "UTF-8"));
    }

    private CompletableFuture<TenantSecurityKMSClient> getClient() {
        return TenantSecurityKMSClient.create("http://localhost:7777", this.INTEGRATION_API_KEY);
    }

    private Map<String, byte[]> getRoundtripDataToEncrypt() throws Exception {
        Map<String, byte[]> documentMap = new HashMap<>();
        documentMap.put("doc1", "Encrypt these bytes!".getBytes("UTF-8"));
        documentMap.put("doc2", "And these bytes!".getBytes("UTF-8"));
        documentMap.put("doc3", "And my axe!".getBytes("UTF-8"));
        return documentMap;
    }

    private DocumentMetadata getRoundtripMetadata(String tenantID) {
        Map<String, String> arbData = new HashMap<>();
        arbData.put("thingOne", "valuetwo");
        return new DocumentMetadata(tenantID, "requestingUserOrServiceID", "dataLabel", arbData, "requestID");
    }

    public void isCiphertextEncryptedDocTest() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.GCP_TENANT_ID);
        Map<String, byte[]> documentMap = getRoundtripDataToEncrypt();

        CompletableFuture<EncryptedDocument> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.encrypt(documentMap, metadata);
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        Map<String, byte[]> encryptedValuesMap = roundtrip.get().getEncryptedFields();
        assertEquals(TenantSecurityKMSClient.isCiphertext(encryptedValuesMap.get("doc1")), true);
        assertEquals(TenantSecurityKMSClient.isCiphertext(encryptedValuesMap.get("doc2")), true);
        assertEquals(TenantSecurityKMSClient.isCiphertext(encryptedValuesMap.get("doc3")), true);
    }

    public void isCiphertextJunkBytesTest() throws Exception {
        assertEquals(TenantSecurityKMSClient.isCiphertext("doom guy".getBytes()), false);
        assertEquals(TenantSecurityKMSClient.isCiphertext("1293982173982398217".getBytes()), false);
        assertEquals(TenantSecurityKMSClient.isCiphertext(new byte[0]), false);
    }

    public void encryptBytesWithExistingKey() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.GCP_TENANT_ID);

        Map<String, byte[]> originalFields = new HashMap<>();
        originalFields.put("doc1", "First time doc".getBytes("UTF-8"));

        Map<String, byte[]> updatedFields = new HashMap<>();
        updatedFields.put("doc1", "Updated doc with new data".getBytes("UTF-8"));

        CompletableFuture<PlaintextDocument> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.encrypt(originalFields, metadata).thenCompose(firstEncryptResult -> {
                    PlaintextDocument updatedDoc = new PlaintextDocument(updatedFields, firstEncryptResult.getEdek());
                    return client.encrypt(updatedDoc, metadata).thenCompose(updatedEncryptedResults -> {
                        // Attempt to decrypt the updated field with the key from the first encrypt to
                        // prove that that it still works
                        return client.decrypt(updatedEncryptedResults, metadata);
                    });
                });
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        Map<String, byte[]> decryptedValuesMap = roundtrip.get().getDecryptedFields();
        assertEqualBytes(decryptedValuesMap.get("doc1"), updatedFields.get("doc1"));
    }

    public void roundTripAWSKMSTest() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.AWS_TENANT_ID);
        Map<String, byte[]> documentMap = getRoundtripDataToEncrypt();

        CompletableFuture<PlaintextDocument> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.encrypt(documentMap, metadata).thenCompose(encryptedResults -> {
                    return client.decrypt(encryptedResults, metadata);
                });
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        Map<String, byte[]> decryptedValuesMap = roundtrip.get().getDecryptedFields();
        assertEqualBytes(decryptedValuesMap.get("doc1"), documentMap.get("doc1"));
        assertEqualBytes(decryptedValuesMap.get("doc2"), documentMap.get("doc2"));
        assertEqualBytes(decryptedValuesMap.get("doc3"), documentMap.get("doc3"));
    }

    public void roundTripGCPKMSTest() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.GCP_TENANT_ID);
        Map<String, byte[]> documentMap = getRoundtripDataToEncrypt();

        CompletableFuture<PlaintextDocument> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.encrypt(documentMap, metadata).thenCompose(encryptedResults -> {
                    return client.decrypt(encryptedResults, metadata);
                });
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        Map<String, byte[]> decryptedValuesMap = roundtrip.get().getDecryptedFields();
        assertEqualBytes(decryptedValuesMap.get("doc1"), documentMap.get("doc1"));
        assertEqualBytes(decryptedValuesMap.get("doc2"), documentMap.get("doc2"));
        assertEqualBytes(decryptedValuesMap.get("doc3"), documentMap.get("doc3"));
    }

    public void roundTripAzureKMSTest() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.AZURE_TENANT_ID);
        Map<String, byte[]> documentMap = getRoundtripDataToEncrypt();

        CompletableFuture<PlaintextDocument> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.encrypt(documentMap, metadata).thenCompose(encryptedResults -> {
                    return client.decrypt(encryptedResults, metadata);
                });
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        Map<String, byte[]> decryptedValuesMap = roundtrip.get().getDecryptedFields();
        assertEqualBytes(decryptedValuesMap.get("doc1"), documentMap.get("doc1"));
        assertEqualBytes(decryptedValuesMap.get("doc2"), documentMap.get("doc2"));
        assertEqualBytes(decryptedValuesMap.get("doc3"), documentMap.get("doc3"));
    }

    public void batchRoundtripTest() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.GCP_TENANT_ID);
        Map<String, byte[]> firstRow = getRoundtripDataToEncrypt();

        Map<String, byte[]> secondRow = new HashMap<>();
        secondRow.put("second1", "And a one!".getBytes("UTF-8"));
        secondRow.put("second2", "And a two!".getBytes("UTF-8"));
        secondRow.put("second3", "And a here we go!".getBytes("UTF-8"));

        Map<String, byte[]> thirdRow = getRoundtripDataToEncrypt();

        Map<String, byte[]> fourthRow = new HashMap<>();
        fourthRow.put("fourth1", "So much encryption!".getBytes("UTF-8"));
        fourthRow.put("fourth2", "Much wow!".getBytes("UTF-8"));
        fourthRow.put("fourth3", "-Doge".getBytes("UTF-8"));

        Map<String, byte[]> fifthRow = getRoundtripDataToEncrypt();

        List<Map<String, byte[]>> rows = Arrays.asList(firstRow, secondRow, thirdRow, fourthRow, fifthRow);

        CompletableFuture<List<PlaintextDocument>> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.encryptBatch(rows, metadata).thenCompose(encryptedList -> {
                    return client.decryptBatch(encryptedList, metadata);
                });
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        List<PlaintextDocument> encryptedRows = roundtrip.get();

        Map<String, byte[]> row1 = encryptedRows.get(0).getDecryptedFields();
        Map<String, byte[]> row2 = encryptedRows.get(1).getDecryptedFields();
        Map<String, byte[]> row3 = encryptedRows.get(2).getDecryptedFields();
        Map<String, byte[]> row4 = encryptedRows.get(3).getDecryptedFields();
        Map<String, byte[]> row5 = encryptedRows.get(4).getDecryptedFields();

        assertEqualBytes(row1.get("doc1"), firstRow.get("doc1"));
        assertEqualBytes(row1.get("doc2"), firstRow.get("doc2"));
        assertEqualBytes(row1.get("doc3"), firstRow.get("doc3"));

        assertEqualBytes(row2.get("second1"), secondRow.get("second1"));
        assertEqualBytes(row2.get("second2"), secondRow.get("second2"));
        assertEqualBytes(row2.get("second3"), secondRow.get("second3"));

        assertEqualBytes(row3.get("doc1"), thirdRow.get("doc1"));
        assertEqualBytes(row3.get("doc2"), thirdRow.get("doc2"));
        assertEqualBytes(row3.get("doc3"), thirdRow.get("doc3"));

        assertEqualBytes(row4.get("fourth1"), fourthRow.get("fourth1"));
        assertEqualBytes(row4.get("fourth2"), fourthRow.get("fourth2"));
        assertEqualBytes(row4.get("fourth3"), fourthRow.get("fourth3"));

        assertEqualBytes(row5.get("doc1"), fifthRow.get("doc1"));
        assertEqualBytes(row5.get("doc2"), fifthRow.get("doc2"));
        assertEqualBytes(row5.get("doc3"), fifthRow.get("doc3"));
    }

    public void batchRoundtripUpdateTest() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.AZURE_TENANT_ID);

        // Create three "rows" of data
        Map<String, byte[]> firstRow = new HashMap<>();
        firstRow.put("first1", "And a one!".getBytes("UTF-8"));
        firstRow.put("first2", "And a two!".getBytes("UTF-8"));
        firstRow.put("first3", "And a here we go!".getBytes("UTF-8"));

        Map<String, byte[]> secondRow = getRoundtripDataToEncrypt();

        Map<String, byte[]> thirdRow = new HashMap<>();
        thirdRow.put("third1", "So much encryption!".getBytes("UTF-8"));
        thirdRow.put("third2", "Much wow!".getBytes("UTF-8"));
        thirdRow.put("third3", "-Doge".getBytes("UTF-8"));

        // Create two modifications of that data (we do this here since the getBytes can
        // throw so doing it within the CompletableFuture workflow is a PITA)
        Map<String, byte[]> newFirstRow = new HashMap<>();
        newFirstRow.put("first2", "And a two!?".getBytes("UTF-8"));

        Map<String, byte[]> newThirdRow = new HashMap<>();
        newThirdRow.put("third3", "-Doge?".getBytes("UTF-8"));

        List<Map<String, byte[]>> rows = Arrays.asList(firstRow, secondRow, thirdRow);

        CompletableFuture<List<PlaintextDocument>> roundtrip = getClient().thenCompose(client -> {
            try {
                // First encrypt the original list of documents via batch operation
                return client.encryptBatch(rows, metadata).thenCompose(encryptedList -> {
                    // Then batch update a few pieces of data from each row with new data but the
                    // same key they used to encrypt
                    PlaintextDocument firstRowUpdates = new PlaintextDocument(newFirstRow,
                            encryptedList.get(0).getEdek());
                    PlaintextDocument thirdRowUpdates = new PlaintextDocument(newThirdRow,
                            encryptedList.get(2).getEdek());

                    // And batch encrypt those new fields
                    return client.encryptExistingBatch(Arrays.asList(firstRowUpdates, thirdRowUpdates), metadata)
                            .thenCompose(updatedEncryptedList -> {
                                // Then merge the newly encrypted fields with the original row of encrypted data
                                // so we can verify that decryption works on all of them with the same key
                                Map<String, byte[]> fullEncryptedFirstRow = new HashMap<>();
                                fullEncryptedFirstRow.putAll(encryptedList.get(0).getEncryptedFields());
                                fullEncryptedFirstRow.putAll(updatedEncryptedList.get(0).getEncryptedFields());

                                Map<String, byte[]> fullEncryptedThirdRow = new HashMap<>();
                                fullEncryptedThirdRow.putAll(encryptedList.get(2).getEncryptedFields());
                                fullEncryptedThirdRow.putAll(updatedEncryptedList.get(1).getEncryptedFields());

                                List<EncryptedDocument> mergedEncryptedList = Arrays.asList(
                                        new EncryptedDocument(fullEncryptedFirstRow, encryptedList.get(0).getEdek()),
                                        encryptedList.get(1),
                                        new EncryptedDocument(fullEncryptedThirdRow, encryptedList.get(2).getEdek()));
                                // Finally decrypt the whole enchilada so we can verify the roundtrip below
                                return client.decryptBatch(mergedEncryptedList, metadata);
                            });
                });
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        List<PlaintextDocument> encryptedRows = roundtrip.get();

        Map<String, byte[]> row1 = encryptedRows.get(0).getDecryptedFields();
        Map<String, byte[]> row2 = encryptedRows.get(1).getDecryptedFields();
        Map<String, byte[]> row3 = encryptedRows.get(2).getDecryptedFields();

        assertEqualBytes(row1.get("first1"), firstRow.get("first1"));
        assertEqualBytes(row1.get("first2"), newFirstRow.get("first2"));
        assertEqualBytes(row1.get("first3"), firstRow.get("first3"));

        assertEqualBytes(row2.get("doc1"), secondRow.get("doc1"));
        assertEqualBytes(row2.get("doc2"), secondRow.get("doc2"));
        assertEqualBytes(row2.get("doc3"), secondRow.get("doc3"));

        assertEqualBytes(row3.get("third1"), thirdRow.get("third1"));
        assertEqualBytes(row3.get("third2"), thirdRow.get("third2"));
        assertEqualBytes(row3.get("third3"), newThirdRow.get("third3"));
    }

    public void largeBatchTest() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.AWS_TENANT_ID);

        // Build up a fairly large amount of data to have a test that encrypts more than
        // a few bytes
        Map<String, byte[]> document = new HashMap<>();

        int msgSize = 1024 * 3000; // 3 MB
        StringBuilder sb = new StringBuilder(msgSize);
        for (int i = 0; i < msgSize; i++) {
            sb.append("a");
        }
        document.put("doc1", sb.toString().getBytes("UTF-8"));

        // Encrypt the document 50 times. Allows us to somewhat stress-test the TSP and
        // the Java client
        List<Map<String, byte[]>> rows = Arrays.asList(document, document, document, document, document, document,
                document, document, document, document, document, document, document, document, document, document,
                document, document, document, document, document, document, document, document, document, document,
                document, document, document, document, document, document, document, document, document, document,
                document, document, document, document, document, document, document, document, document, document,
                document, document, document, document);

        CompletableFuture<List<PlaintextDocument>> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.encryptBatch(rows, metadata).thenCompose(encryptedResults -> {
                    return client.decryptBatch(encryptedResults, metadata);
                });
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        List<PlaintextDocument> decryptedValues = roundtrip.get();
        assertEquals(decryptedValues.size(), 50);
    }
}