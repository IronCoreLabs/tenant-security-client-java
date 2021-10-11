package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.stream.Collectors;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.logdriver.v1.EventMetadata;
import com.ironcorelabs.tenantsecurity.logdriver.v1.UserEvent;

import org.testng.annotations.Test;

@Test(groups = { "dev-integration" })
public class DevIntegrationTest {
    private String GCP_TENANT_ID = "INTEGRATION-TEST-DEV1-GCP";
    private String AWS_TENANT_ID = "INTEGRATION-TEST-DEV1-AWS";
    private String AZURE_TENANT_ID = "INTEGRATION-TEST-DEV1-AZURE";
    private String INTEGRATION_API_KEY = System.getenv("API_KEY");

    @Test(expectedExceptions = java.net.MalformedURLException.class)
    public void constructorUrlTest() throws Exception {
        new TenantSecurityClient("foobaz", "apiKey").close();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void missingApiKeyTest() throws Exception {
        new TenantSecurityClient("http://localhost", null).close();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void emptyApiKeyTest() throws Exception {
        new TenantSecurityClient("http://localhost", "").close();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void invalidRequestThreadpoolSize() throws Exception {
        new TenantSecurityClient("http://localhost", "apiKey", 0, 1).close();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void invalidCryptoThreadpoolSize() throws Exception {
        new TenantSecurityClient("http://localhost", "apiKey", 1, 0).close();
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void missingRandomGen() throws Exception {
        new TenantSecurityClient("http://localhost", "apiKey", TenantSecurityClient.DEFAULT_REQUEST_THREADPOOL_SIZE,
                TenantSecurityClient.DEFAULT_AES_THREADPOOL_SIZE, null).close();
    }

    private void assertEqualBytes(byte[] one, byte[] two) throws Exception {
        assertEquals(new String(one, "UTF-8"), new String(two, "UTF-8"));
    }

    private CompletableFuture<TenantSecurityClient> getClient() {
        return TenantSecurityClient.create(TestSettings.TSP_ADDRESS + TestSettings.TSP_PORT, this.INTEGRATION_API_KEY);
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
        assertEquals(CryptoUtils.isCiphertext(encryptedValuesMap.get("doc1")), true);
        assertEquals(CryptoUtils.isCiphertext(encryptedValuesMap.get("doc2")), true);
        assertEquals(CryptoUtils.isCiphertext(encryptedValuesMap.get("doc3")), true);
    }

    public void isCiphertextJunkBytesTest() throws Exception {
        assertEquals(CryptoUtils.isCiphertext("doom guy".getBytes()), false);
        assertEquals(CryptoUtils.isCiphertext("1293982173982398217".getBytes()), false);
        assertEquals(CryptoUtils.isCiphertext(new byte[0]), false);
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
                        // Attempt to decrypt the updated field with the key from the first
                        // encrypt to prove that that it still works
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

    public void roundTripRekeyAWSToAzure() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.AWS_TENANT_ID);
        Map<String, byte[]> documentMap = getRoundtripDataToEncrypt();

        CompletableFuture<PlaintextDocument> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.encrypt(documentMap, metadata).thenCompose(encryptedResults -> {
                    return client.rekeyDocument(encryptedResults, metadata, this.AZURE_TENANT_ID)
                            .thenCompose(rekeyResults -> {
                                assertEquals(rekeyResults.getEncryptedFields(), encryptedResults.getEncryptedFields());
                                DocumentMetadata newMetadata = getRoundtripMetadata(this.AZURE_TENANT_ID);
                                return client.decrypt(rekeyResults, newMetadata);
                            });
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

        HashMap<String, Map<String, byte[]>> batchRows = new HashMap<>();
        batchRows.put("firstRow", firstRow);
        batchRows.put("secondRow", secondRow);
        batchRows.put("thirdRow", thirdRow);

        CompletableFuture<BatchResult<PlaintextDocument>> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.encryptBatch(batchRows, metadata).thenCompose(batchResult -> {
                    assertEquals(0, batchResult.getFailures().size());
                    assertEquals(3, batchResult.getDocuments().size());
                    return client.decryptBatch(batchResult.getDocuments(), metadata);
                });
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        BatchResult<PlaintextDocument> decryptedBatch = roundtrip.get();
        assertEquals(0, decryptedBatch.getFailures().size());
        assertEquals(3, decryptedBatch.getDocuments().size());

        Map<String, PlaintextDocument> decryptedRows = decryptedBatch.getDocuments();
        Map<String, byte[]> row1 = decryptedRows.get("firstRow").getDecryptedFields();
        Map<String, byte[]> row2 = decryptedRows.get("secondRow").getDecryptedFields();
        Map<String, byte[]> row3 = decryptedRows.get("thirdRow").getDecryptedFields();

        assertEqualBytes(row1.get("doc1"), firstRow.get("doc1"));
        assertEqualBytes(row1.get("doc2"), firstRow.get("doc2"));
        assertEqualBytes(row1.get("doc3"), firstRow.get("doc3"));

        assertEqualBytes(row2.get("second1"), secondRow.get("second1"));
        assertEqualBytes(row2.get("second2"), secondRow.get("second2"));
        assertEqualBytes(row2.get("second3"), secondRow.get("second3"));

        assertEqualBytes(row3.get("doc1"), thirdRow.get("doc1"));
        assertEqualBytes(row3.get("doc2"), thirdRow.get("doc2"));
        assertEqualBytes(row3.get("doc3"), thirdRow.get("doc3"));
    }

    public void batchRoundtripUpdateTest() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.AZURE_TENANT_ID);

        // Create three "rows" of data
        Map<String, byte[]> user10 = new HashMap<>();
        user10.put("name", "And a one!".getBytes("UTF-8"));
        user10.put("email", "And a two!".getBytes("UTF-8"));
        user10.put("birthday", "And a here we go!".getBytes("UTF-8"));

        Map<String, byte[]> user20 = new HashMap<>();
        user20.put("name", "John Doe".getBytes("UTF-8"));
        user20.put("email", "jd@example.com".getBytes("UTF-8"));
        user20.put("birthday", "12/20/1993".getBytes("UTF-8"));

        Map<String, byte[]> user30 = new HashMap<>();
        user30.put("name", "So much encryption!".getBytes("UTF-8"));
        user30.put("email", "Much wow!".getBytes("UTF-8"));
        user30.put("birthday", "-Doge".getBytes("UTF-8"));

        // Create two modifications of that data (we do this here since the getBytes can
        // throw so doing it within the CompletableFuture workflow is a PITA)
        Map<String, byte[]> newUser10 = new HashMap<>();
        newUser10.put("email", "And a two!?".getBytes("UTF-8"));

        Map<String, byte[]> newUser30 = new HashMap<>();
        newUser30.put("birthday", "-Doge?".getBytes("UTF-8"));

        Map<String, Map<String, byte[]>> batchRows = new HashMap<>();
        batchRows.put("user10", user10);
        batchRows.put("user20", user20);
        batchRows.put("user30", user30);

        CompletableFuture<BatchResult<PlaintextDocument>> roundtrip = getClient().thenCompose(client -> {
            try {
                // First encrypt the original list of documents via batch operation
                return client.encryptBatch(batchRows, metadata).thenCompose(initialEncryptResults -> {
                    assertEquals(0, initialEncryptResults.getFailures().size());
                    assertEquals(3, initialEncryptResults.getDocuments().size());
                    // Then batch update a few pieces of data from each row with new
                    // data but the same key they used to encrypt
                    PlaintextDocument user10Updates = new PlaintextDocument(newUser10,
                            initialEncryptResults.getDocuments().get("user10").getEdek());
                    PlaintextDocument user30Updates = new PlaintextDocument(newUser30,
                            initialEncryptResults.getDocuments().get("user30").getEdek());

                    Map<String, PlaintextDocument> updateBatch = new HashMap<>();
                    updateBatch.put("user10", user10Updates);
                    updateBatch.put("user30", user30Updates);

                    // And batch encrypt those new fields
                    return client.encryptExistingBatch(updateBatch, metadata).thenCompose(batchUpdateResult -> {
                        assertEquals(0, batchUpdateResult.getFailures().size());
                        assertEquals(2, batchUpdateResult.getDocuments().size());
                        Map<String, EncryptedDocument> updateSuccesses = batchUpdateResult.getDocuments();
                        // Then merge the newly encrypted fields with the
                        // original row of encrypted data so we can verify
                        // that decryption works on all of them with the
                        // same key
                        Map<String, byte[]> fullEncryptedUser10 = new HashMap<>();
                        fullEncryptedUser10
                                .putAll(initialEncryptResults.getDocuments().get("user10").getEncryptedFields());
                        fullEncryptedUser10.putAll(updateSuccesses.get("user10").getEncryptedFields());

                        Map<String, byte[]> fullEncryptedUser30 = new HashMap<>();
                        fullEncryptedUser30
                                .putAll(initialEncryptResults.getDocuments().get("user30").getEncryptedFields());
                        fullEncryptedUser30.putAll(updateSuccesses.get("user30").getEncryptedFields());

                        Map<String, EncryptedDocument> mergedEncryptedList = new HashMap<>();
                        mergedEncryptedList.put("user10", new EncryptedDocument(fullEncryptedUser10,
                                initialEncryptResults.getDocuments().get("user10").getEdek()));
                        mergedEncryptedList.put("user20", initialEncryptResults.getDocuments().get("user20"));
                        mergedEncryptedList.put("user30", new EncryptedDocument(fullEncryptedUser30,
                                initialEncryptResults.getDocuments().get("user30").getEdek()));
                        // Finally decrypt the whole enchilada so we can
                        // verify the roundtrip below
                        return client.decryptBatch(mergedEncryptedList, metadata);
                    });
                });
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        BatchResult<PlaintextDocument> fullBatchResult = roundtrip.get();
        Map<String, PlaintextDocument> successes = fullBatchResult.getDocuments();
        Map<String, TenantSecurityException> failures = fullBatchResult.getFailures();

        assertEquals(0, failures.size());
        assertEquals(3, successes.size());

        Map<String, byte[]> roundtripUser10 = successes.get("user10").getDecryptedFields();
        Map<String, byte[]> roundtripUser20 = successes.get("user20").getDecryptedFields();
        Map<String, byte[]> roundtripUser30 = successes.get("user30").getDecryptedFields();

        assertEqualBytes(roundtripUser10.get("name"), user10.get("name"));
        assertEqualBytes(roundtripUser10.get("email"), newUser10.get("email"));
        assertEqualBytes(roundtripUser10.get("birthday"), user10.get("birthday"));

        assertEqualBytes(roundtripUser20.get("name"), user20.get("name"));
        assertEqualBytes(roundtripUser20.get("email"), user20.get("email"));
        assertEqualBytes(roundtripUser20.get("birthday"), user20.get("birthday"));

        assertEqualBytes(roundtripUser30.get("name"), user30.get("name"));
        assertEqualBytes(roundtripUser30.get("email"), user30.get("email"));
        assertEqualBytes(roundtripUser30.get("birthday"), newUser30.get("birthday"));
    }

    public void largeBatchTest() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.AWS_TENANT_ID);

        // Build up a fairly large amount of data to have a test that encrypts more than
        // a few bytes
        Map<String, byte[]> document = new HashMap<>();
        int batchSize = 50;
        int msgSize = 1024 * 3000; // 3 MB
        StringBuilder sb = new StringBuilder(msgSize);
        for (int i = 0; i < msgSize; i++) {
            sb.append("a");
        }
        document.put("doc1", sb.toString().getBytes("UTF-8"));

        // Encrypt the document 50 times. Allows us to somewhat stress-test the TSP and
        // the Java client
        List<Map<String, byte[]>> rows = Arrays.stream(new int[batchSize]).mapToObj(_nope -> document)
                .collect(Collectors.toList());

        Map<String, Map<String, byte[]>> batch = new HashMap<>();
        for (int i = 0; i < rows.size(); i++) {
            batch.put(Integer.toString(i), rows.get(i));
        }

        CompletableFuture<BatchResult<PlaintextDocument>> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.encryptBatch(batch, metadata).thenCompose(batchEncryptedResults -> {
                    assertEquals(0, batchEncryptedResults.getFailures().size());
                    assertEquals(batchSize, batchEncryptedResults.getDocuments().size());
                    return client.decryptBatch(batchEncryptedResults.getDocuments(), metadata);
                });
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        BatchResult<PlaintextDocument> decryptedValues = roundtrip.get();
        assertEquals(0, decryptedValues.getFailures().size());
        assertEquals(batchSize, decryptedValues.getDocuments().size());
    }

    public void leasedDataTest() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata(this.GCP_TENANT_ID);

        String leasedDocumentEdek = "Cr8BCjA7nnuAiXpD0Jkjc6mOBgcSyxcjFYX813WQhhYg0oKnsDJTmeyAaLs3t9pzkR6mU9cQ7AMY3gQiDCEN6aQFtglBZ0DX7yp3CnUKcAokABW+8Gfu/FSC8WQTqxw528aQXwrpvY0MjlHurZJ6yHx9S/2zEkgAs0w57oTuIHzVmauLGDi/S9zCQH20dezcc/jtw/nqCDnAtAPSB9m17YvGOVpN5xO8960C86NA4AJCoVJ291YW9OkIKto48/YQ7AM=";
        String leasedDocumentBytes = "A0lST04AOwocjKi8E65AAxBCqUjeSqQDc7veZVQehempBfsABBobChlJTlRFR1JBVElPTi1URVNULURFVjEtR0NQbZ+1yhYOoCNdtV+VVTMTUfAQm1FdqtGyjqeE7iYxfW9TKwTc2C0=";

        Map<String, byte[]> documentMap = new HashMap<>();
        documentMap.put("doc", Base64.getDecoder().decode(leasedDocumentBytes));
        EncryptedDocument leasedDoc = new EncryptedDocument(documentMap, leasedDocumentEdek);

        CompletableFuture<PlaintextDocument> roundtrip = getClient().thenCompose(client -> {
            try {
                return client.decrypt(leasedDoc, metadata);
            } catch (Exception e) {
                throw new CompletionException(e);
            }
        });

        Map<String, byte[]> decryptedValuesMap = roundtrip.get().getDecryptedFields();
        assertEqualBytes(decryptedValuesMap.get("doc"), "new daters".getBytes("UTF-8"));
    }

    public void logSecurityEvent() throws Exception {
        EventMetadata metadata = new EventMetadata(this.GCP_TENANT_ID, "integrationTest", "sample", "app-request-id");
        CompletableFuture<Void> logEvent = getClient()
                .thenCompose(client -> client.logSecurityEvent(UserEvent.ADD, metadata));

        try {
            logEvent.get();
        } catch (Exception e) {
            fail("Security Event logging should not fail");
        }

    }

}
