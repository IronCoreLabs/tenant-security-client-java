package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import com.ironcorelabs.tenantsecurity.TestUtils;
import org.testng.annotations.Test;

@Test(groups = {"local-integration"})
public class CachedKeyOpsRoundTrip {
  private static String TENANT_ID = "tenant-gcp";
  private static String API_KEY = "0WUaXesNgbTAuLwn";

  private void assertEqualBytes(byte[] one, byte[] two) throws Exception {
    assertEquals(new String(one, "UTF-8"), new String(two, "UTF-8"));
  }

  private CompletableFuture<TenantSecurityClient> getClient() {
    Map<String, String> envVars = System.getenv();
    String tsp_address = envVars.getOrDefault("TSP_ADDRESS", TestSettings.TSP_ADDRESS);
    String tsp_port =
        TestUtils.ensureLeadingColon(envVars.getOrDefault("TSP_PORT", TestSettings.TSP_PORT));
    String api_key = envVars.getOrDefault("API_KEY", API_KEY);
    return TestUtils.createTscWithAllowInsecure(tsp_address + tsp_port, api_key);
  }

  private DocumentMetadata getMetadata() {
    Map<String, String> envVars = System.getenv();
    String tenant_id = envVars.getOrDefault("TENANT_ID", TENANT_ID);
    return new DocumentMetadata(tenant_id, "integrationTest", "cachedKeyOps");
  }

  private Map<String, byte[]> getDocumentFields() throws Exception {
    Map<String, byte[]> documentMap = new HashMap<>();
    documentMap.put("field1", "First field data".getBytes("UTF-8"));
    documentMap.put("field2", "Second field data".getBytes("UTF-8"));
    documentMap.put("field3", "Third field data".getBytes("UTF-8"));
    return documentMap;
  }

  // === CachedKeyEncryptor tests ===

  public void cachedEncryptorRoundTrip() throws Exception {
    DocumentMetadata metadata = getMetadata();
    Map<String, byte[]> doc1 = getDocumentFields();
    Map<String, byte[]> doc2 = new HashMap<>();
    doc2.put("other", "Other document data".getBytes("UTF-8"));

    TenantSecurityClient client = getClient().get();

    try (CachedKeyEncryptor encryptor = client.createCachedEncryptor(metadata).get()) {
      assertFalse(encryptor.isClosed());
      assertFalse(encryptor.isExpired());
      assertEquals(encryptor.getOperationCount(), 0);

      // Encrypt two documents with the cached encryptor
      EncryptedDocument enc1 = encryptor.encrypt(doc1, metadata).get();
      EncryptedDocument enc2 = encryptor.encrypt(doc2, metadata).get();

      assertEquals(encryptor.getOperationCount(), 2);

      // All documents should share the same EDEK
      assertEquals(enc1.getEdek(), enc2.getEdek());
      assertEquals(enc1.getEdek(), encryptor.getEdek());

      // Decrypt with standard client and verify roundtrip
      PlaintextDocument dec1 = client.decrypt(enc1, metadata).get();
      PlaintextDocument dec2 = client.decrypt(enc2, metadata).get();

      assertEqualBytes(dec1.getDecryptedFields().get("field1"), doc1.get("field1"));
      assertEqualBytes(dec1.getDecryptedFields().get("field2"), doc1.get("field2"));
      assertEqualBytes(dec1.getDecryptedFields().get("field3"), doc1.get("field3"));
      assertEqualBytes(dec2.getDecryptedFields().get("other"), doc2.get("other"));
    }

    client.close();
  }

  public void cachedEncryptorWithPattern() throws Exception {
    DocumentMetadata metadata = getMetadata();
    Map<String, byte[]> doc = getDocumentFields();

    TenantSecurityClient client = getClient().get();

    // Use the withCachedEncryptor pattern for automatic lifecycle management
    EncryptedDocument encrypted =
        client.withCachedEncryptor(metadata, encryptor -> encryptor.encrypt(doc, metadata)).get();

    // Verify the encrypted document can be decrypted
    PlaintextDocument decrypted = client.decrypt(encrypted, metadata).get();
    assertEqualBytes(decrypted.getDecryptedFields().get("field1"), doc.get("field1"));
    assertEqualBytes(decrypted.getDecryptedFields().get("field2"), doc.get("field2"));
    assertEqualBytes(decrypted.getDecryptedFields().get("field3"), doc.get("field3"));

    client.close();
  }

  // === CachedKeyDecryptor tests ===

  public void cachedDecryptorRoundTrip() throws Exception {
    DocumentMetadata metadata = getMetadata();
    Map<String, byte[]> doc1 = getDocumentFields();
    Map<String, byte[]> doc2 = new HashMap<>();
    doc2.put("other", "Other document data".getBytes("UTF-8"));

    TenantSecurityClient client = getClient().get();

    // Encrypt two documents with the same key (using cached encryptor)
    EncryptedDocument enc1;
    EncryptedDocument enc2;
    try (CachedKeyEncryptor encryptor = client.createCachedEncryptor(metadata).get()) {
      enc1 = encryptor.encrypt(doc1, metadata).get();
      enc2 = encryptor.encrypt(doc2, metadata).get();
    }

    // Decrypt both using a cached decryptor (single unwrap call)
    try (CachedKeyDecryptor decryptor =
        client.createCachedDecryptor(enc1.getEdek(), metadata).get()) {
      assertFalse(decryptor.isClosed());
      assertFalse(decryptor.isExpired());
      assertEquals(decryptor.getOperationCount(), 0);

      PlaintextDocument dec1 = decryptor.decrypt(enc1, metadata).get();
      PlaintextDocument dec2 = decryptor.decrypt(enc2, metadata).get();

      assertEquals(decryptor.getOperationCount(), 2);

      assertEqualBytes(dec1.getDecryptedFields().get("field1"), doc1.get("field1"));
      assertEqualBytes(dec1.getDecryptedFields().get("field2"), doc1.get("field2"));
      assertEqualBytes(dec1.getDecryptedFields().get("field3"), doc1.get("field3"));
      assertEqualBytes(dec2.getDecryptedFields().get("other"), doc2.get("other"));
    }

    client.close();
  }

  public void cachedDecryptorFromEncryptedDocument() throws Exception {
    DocumentMetadata metadata = getMetadata();
    Map<String, byte[]> doc = getDocumentFields();

    TenantSecurityClient client = getClient().get();

    EncryptedDocument encrypted = client.encrypt(doc, metadata).get();

    // Create decryptor from EncryptedDocument directly
    try (CachedKeyDecryptor decryptor = client.createCachedDecryptor(encrypted, metadata).get()) {
      PlaintextDocument decrypted = decryptor.decrypt(encrypted, metadata).get();
      assertEqualBytes(decrypted.getDecryptedFields().get("field1"), doc.get("field1"));
      assertEqualBytes(decrypted.getDecryptedFields().get("field2"), doc.get("field2"));
      assertEqualBytes(decrypted.getDecryptedFields().get("field3"), doc.get("field3"));
    }

    client.close();
  }

  public void cachedDecryptorWithPattern() throws Exception {
    DocumentMetadata metadata = getMetadata();
    Map<String, byte[]> doc = getDocumentFields();

    TenantSecurityClient client = getClient().get();

    EncryptedDocument encrypted = client.encrypt(doc, metadata).get();

    // Use the withCachedDecryptor pattern for automatic lifecycle management
    PlaintextDocument decrypted = client.withCachedDecryptor(encrypted, metadata,
        decryptor -> decryptor.decrypt(encrypted, metadata)).get();

    assertEqualBytes(decrypted.getDecryptedFields().get("field1"), doc.get("field1"));
    assertEqualBytes(decrypted.getDecryptedFields().get("field2"), doc.get("field2"));
    assertEqualBytes(decrypted.getDecryptedFields().get("field3"), doc.get("field3"));

    client.close();
  }

  // === Streaming tests ===

  public void cachedEncryptorStreamRoundTrip() throws Exception {
    DocumentMetadata metadata = getMetadata();
    byte[] plaintext = "Stream encrypt with cached key test data".getBytes("UTF-8");

    TenantSecurityClient client = getClient().get();

    ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();
    String edek;

    try (CachedKeyEncryptor encryptor = client.createCachedEncryptor(metadata).get()) {
      ByteArrayInputStream input = new ByteArrayInputStream(plaintext);
      StreamingResponse response = encryptor.encryptStream(input, encryptedOutput, metadata).get();
      edek = response.getEdek();
      assertEquals(encryptor.getOperationCount(), 1);
      // EDEK from streaming response should match the encryptor's EDEK
      assertEquals(edek, encryptor.getEdek());
    }

    // Decrypt with standard client
    ByteArrayInputStream encryptedInput = new ByteArrayInputStream(encryptedOutput.toByteArray());
    ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream();
    client.decryptStream(edek, encryptedInput, decryptedOutput, metadata).get();

    assertEqualBytes(decryptedOutput.toByteArray(), plaintext);

    client.close();
  }

  public void cachedDecryptorStreamRoundTrip() throws Exception {
    DocumentMetadata metadata = getMetadata();
    byte[] plaintext = "Stream decrypt with cached key test data".getBytes("UTF-8");

    TenantSecurityClient client = getClient().get();

    // Encrypt with standard client
    ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();
    ByteArrayInputStream input = new ByteArrayInputStream(plaintext);
    StreamingResponse encResponse = client.encryptStream(input, encryptedOutput, metadata).get();
    String edek = encResponse.getEdek();

    // Decrypt with cached decryptor
    try (CachedKeyDecryptor decryptor = client.createCachedDecryptor(edek, metadata).get()) {
      ByteArrayInputStream encryptedInput = new ByteArrayInputStream(encryptedOutput.toByteArray());
      ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream();
      decryptor.decryptStream(edek, encryptedInput, decryptedOutput, metadata).get();

      assertEquals(decryptor.getOperationCount(), 1);
      assertEqualBytes(decryptedOutput.toByteArray(), plaintext);
    }

    client.close();
  }

  // === Full round-trip: cached encrypt -> cached decrypt ===

  public void cachedEncryptToCachedDecryptRoundTrip() throws Exception {
    DocumentMetadata metadata = getMetadata();
    Map<String, byte[]> doc1 = getDocumentFields();
    Map<String, byte[]> doc2 = new HashMap<>();
    doc2.put("solo", "Solo field document".getBytes("UTF-8"));

    TenantSecurityClient client = getClient().get();

    // Encrypt multiple docs with cached encryptor
    EncryptedDocument enc1;
    EncryptedDocument enc2;
    try (CachedKeyEncryptor encryptor = client.createCachedEncryptor(metadata).get()) {
      enc1 = encryptor.encrypt(doc1, metadata).get();
      enc2 = encryptor.encrypt(doc2, metadata).get();
    }

    // Decrypt all with cached decryptor (one unwrap call for all)
    try (CachedKeyDecryptor decryptor =
        client.createCachedDecryptor(enc1.getEdek(), metadata).get()) {
      PlaintextDocument dec1 = decryptor.decrypt(enc1, metadata).get();
      PlaintextDocument dec2 = decryptor.decrypt(enc2, metadata).get();

      assertEqualBytes(dec1.getDecryptedFields().get("field1"), doc1.get("field1"));
      assertEqualBytes(dec1.getDecryptedFields().get("field2"), doc1.get("field2"));
      assertEqualBytes(dec1.getDecryptedFields().get("field3"), doc1.get("field3"));
      assertEqualBytes(dec2.getDecryptedFields().get("solo"), doc2.get("solo"));
    }

    client.close();
  }

  public void cachedStreamEncryptToCachedStreamDecryptRoundTrip() throws Exception {
    DocumentMetadata metadata = getMetadata();
    byte[] plaintext = "Full cached stream round-trip data".getBytes("UTF-8");

    TenantSecurityClient client = getClient().get();

    // Encrypt stream with cached encryptor
    ByteArrayOutputStream encryptedOutput = new ByteArrayOutputStream();
    String edek;
    try (CachedKeyEncryptor encryptor = client.createCachedEncryptor(metadata).get()) {
      ByteArrayInputStream input = new ByteArrayInputStream(plaintext);
      StreamingResponse response = encryptor.encryptStream(input, encryptedOutput, metadata).get();
      edek = response.getEdek();
    }

    // Decrypt stream with cached decryptor
    try (CachedKeyDecryptor decryptor = client.createCachedDecryptor(edek, metadata).get()) {
      ByteArrayInputStream encryptedInput = new ByteArrayInputStream(encryptedOutput.toByteArray());
      ByteArrayOutputStream decryptedOutput = new ByteArrayOutputStream();
      decryptor.decryptStream(edek, encryptedInput, decryptedOutput, metadata).get();
      assertEqualBytes(decryptedOutput.toByteArray(), plaintext);
    }

    client.close();
  }

  // === Encryptor close behavior ===

  public void cachedEncryptorRejectsAfterClose() throws Exception {
    DocumentMetadata metadata = getMetadata();
    Map<String, byte[]> doc = getDocumentFields();

    TenantSecurityClient client = getClient().get();

    CachedKeyEncryptor encryptor = client.createCachedEncryptor(metadata).get();
    // Encrypt once to verify it works
    encryptor.encrypt(doc, metadata).get();
    assertEquals(encryptor.getOperationCount(), 1);

    // Close and verify it rejects
    encryptor.close();
    assertTrue(encryptor.isClosed());

    try {
      encryptor.encrypt(doc, metadata).get();
      assertTrue(false, "Should have thrown after close");
    } catch (ExecutionException e) {
      assertTrue(e.getCause().getMessage().contains("closed"));
    }

    client.close();
  }

  public void cachedDecryptorRejectsAfterClose() throws Exception {
    DocumentMetadata metadata = getMetadata();
    Map<String, byte[]> doc = getDocumentFields();

    TenantSecurityClient client = getClient().get();

    EncryptedDocument encrypted = client.encrypt(doc, metadata).get();

    CachedKeyDecryptor decryptor =
        client.createCachedDecryptor(encrypted.getEdek(), metadata).get();
    // Decrypt once to verify it works
    decryptor.decrypt(encrypted, metadata).get();
    assertEquals(decryptor.getOperationCount(), 1);

    // Close and verify it rejects
    decryptor.close();
    assertTrue(decryptor.isClosed());

    try {
      decryptor.decrypt(encrypted, metadata).get();
      assertTrue(false, "Should have thrown after close");
    } catch (ExecutionException e) {
      assertTrue(e.getCause().getMessage().contains("closed"));
    }

    client.close();
  }

  // === EDEK mismatch ===

  // === Batch encrypt/decrypt tests ===

  public void cachedEncryptorBatchRoundTrip() throws Exception {
    DocumentMetadata metadata = getMetadata();

    Map<String, Map<String, byte[]>> docs = new HashMap<>();
    docs.put("doc1", getDocumentFields());
    Map<String, byte[]> doc2 = new HashMap<>();
    doc2.put("other", "Other data".getBytes("UTF-8"));
    docs.put("doc2", doc2);
    Map<String, byte[]> doc3 = new HashMap<>();
    doc3.put("solo", "Solo data".getBytes("UTF-8"));
    docs.put("doc3", doc3);

    TenantSecurityClient client = getClient().get();

    BatchResult<EncryptedDocument> encResult;
    try (CachedKeyEncryptor encryptor = client.createCachedEncryptor(metadata).get()) {
      encResult = encryptor.encryptBatch(docs, metadata).get();
      assertEquals(encryptor.getOperationCount(), 3);
    }

    assertFalse(encResult.hasFailures());
    assertEquals(encResult.getSuccesses().size(), 3);

    // All encrypted docs share the same EDEK
    String commonEdek = encResult.getSuccesses().values().iterator().next().getEdek();
    for (EncryptedDocument enc : encResult.getSuccesses().values()) {
      assertEquals(enc.getEdek(), commonEdek);
    }

    // Decrypt each with standard client and verify roundtrip
    PlaintextDocument dec1 = client.decrypt(encResult.getSuccesses().get("doc1"), metadata).get();
    assertEqualBytes(dec1.getDecryptedFields().get("field1"), docs.get("doc1").get("field1"));

    PlaintextDocument dec2 = client.decrypt(encResult.getSuccesses().get("doc2"), metadata).get();
    assertEqualBytes(dec2.getDecryptedFields().get("other"), doc2.get("other"));

    PlaintextDocument dec3 = client.decrypt(encResult.getSuccesses().get("doc3"), metadata).get();
    assertEqualBytes(dec3.getDecryptedFields().get("solo"), doc3.get("solo"));

    client.close();
  }

  public void cachedDecryptorBatchRoundTrip() throws Exception {
    DocumentMetadata metadata = getMetadata();

    Map<String, byte[]> doc1 = getDocumentFields();
    Map<String, byte[]> doc2 = new HashMap<>();
    doc2.put("other", "Other data".getBytes("UTF-8"));
    Map<String, byte[]> doc3 = new HashMap<>();
    doc3.put("solo", "Solo data".getBytes("UTF-8"));

    TenantSecurityClient client = getClient().get();

    // Encrypt all 3 with cached encryptor (same key)
    EncryptedDocument enc1, enc2, enc3;
    try (CachedKeyEncryptor encryptor = client.createCachedEncryptor(metadata).get()) {
      enc1 = encryptor.encrypt(doc1, metadata).get();
      enc2 = encryptor.encrypt(doc2, metadata).get();
      enc3 = encryptor.encrypt(doc3, metadata).get();
    }

    // Batch decrypt with cached decryptor
    Map<String, EncryptedDocument> encDocs = new HashMap<>();
    encDocs.put("doc1", enc1);
    encDocs.put("doc2", enc2);
    encDocs.put("doc3", enc3);

    try (CachedKeyDecryptor decryptor =
        client.createCachedDecryptor(enc1.getEdek(), metadata).get()) {
      BatchResult<PlaintextDocument> result = decryptor.decryptBatch(encDocs, metadata).get();
      assertEquals(decryptor.getOperationCount(), 3);

      assertFalse(result.hasFailures());
      assertEquals(result.getSuccesses().size(), 3);

      assertEqualBytes(result.getSuccesses().get("doc1").getDecryptedFields().get("field1"),
          doc1.get("field1"));
      assertEqualBytes(result.getSuccesses().get("doc2").getDecryptedFields().get("other"),
          doc2.get("other"));
      assertEqualBytes(result.getSuccesses().get("doc3").getDecryptedFields().get("solo"),
          doc3.get("solo"));
    }

    client.close();
  }

  public void cachedDecryptorBatchEdekMismatchPartialFailure() throws Exception {
    DocumentMetadata metadata = getMetadata();
    Map<String, byte[]> doc = getDocumentFields();

    TenantSecurityClient client = getClient().get();

    // Encrypt two documents with different keys
    EncryptedDocument enc1 = client.encrypt(doc, metadata).get();
    EncryptedDocument enc2 = client.encrypt(doc, metadata).get();

    Map<String, EncryptedDocument> encDocs = new HashMap<>();
    encDocs.put("match", enc1);
    encDocs.put("mismatch", enc2);

    // Create decryptor for enc1's key
    try (CachedKeyDecryptor decryptor =
        client.createCachedDecryptor(enc1.getEdek(), metadata).get()) {
      BatchResult<PlaintextDocument> result = decryptor.decryptBatch(encDocs, metadata).get();

      // match should succeed
      assertTrue(result.getSuccesses().containsKey("match"));
      assertEqualBytes(result.getSuccesses().get("match").getDecryptedFields().get("field1"),
          doc.get("field1"));

      // mismatch should be in failures
      assertTrue(result.getFailures().containsKey("mismatch"));
      assertTrue(
          result.getFailures().get("mismatch").getMessage().contains("EDEK does not match"));

      assertEquals(decryptor.getOperationCount(), 1);
    }

    client.close();
  }

  public void cachedBatchOperationCount() throws Exception {
    DocumentMetadata metadata = getMetadata();

    Map<String, Map<String, byte[]>> docs = new HashMap<>();
    docs.put("doc1", getDocumentFields());
    Map<String, byte[]> doc2 = new HashMap<>();
    doc2.put("field", "data".getBytes("UTF-8"));
    docs.put("doc2", doc2);

    TenantSecurityClient client = getClient().get();

    try (CachedKeyEncryptor encryptor = client.createCachedEncryptor(metadata).get()) {
      assertEquals(encryptor.getOperationCount(), 0);
      encryptor.encryptBatch(docs, metadata).get();
      assertEquals(encryptor.getOperationCount(), 2);
      // Single encrypt should add 1 more
      encryptor.encrypt(docs.get("doc1"), metadata).get();
      assertEquals(encryptor.getOperationCount(), 3);
    }

    client.close();
  }

  // === EDEK mismatch ===

  public void cachedDecryptorRejectsEdekMismatch() throws Exception {
    DocumentMetadata metadata = getMetadata();
    Map<String, byte[]> doc = getDocumentFields();

    TenantSecurityClient client = getClient().get();

    // Encrypt two documents with different keys
    EncryptedDocument enc1 = client.encrypt(doc, metadata).get();
    EncryptedDocument enc2 = client.encrypt(doc, metadata).get();

    // Create decryptor for enc1's EDEK
    try (CachedKeyDecryptor decryptor =
        client.createCachedDecryptor(enc1.getEdek(), metadata).get()) {
      // Decrypting enc1 should work
      decryptor.decrypt(enc1, metadata).get();

      // Decrypting enc2 (different EDEK) should fail
      try {
        decryptor.decrypt(enc2, metadata).get();
        assertTrue(false, "Should have thrown for EDEK mismatch");
      } catch (ExecutionException e) {
        assertTrue(e.getCause().getMessage().contains("EDEK does not match"));
      }
    }

    client.close();
  }
}
