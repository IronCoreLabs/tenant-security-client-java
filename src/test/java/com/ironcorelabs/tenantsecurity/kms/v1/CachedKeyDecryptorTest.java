package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;

@Test(groups = {"unit"})
public class CachedKeyDecryptorTest {

  private ExecutorService executor;
  private TenantSecurityRequest encryptionService;
  private static final String TEST_EDEK = "test-edek-base64-string";
  private static final String DIFFERENT_EDEK = "different-edek-base64-string";
  private DocumentMetadata metadata =
      new DocumentMetadata("tenantId", "requestingUserOrServiceId", "dataLabel");

  @BeforeClass
  public void setup() {
    executor = Executors.newFixedThreadPool(2);
    // This endpoint doesn't exist, so we won't call `close` on the cached decryptor to avoid the
    // report-operations request
    encryptionService = new TenantSecurityRequest("http://localhost:0", "test-api-key", 1, 1000);
  }

  @AfterClass
  public void teardown() {
    if (executor != null) {
      executor.shutdown();
    }
    if (encryptionService != null) {
      try {
        encryptionService.close();
      } catch (Exception e) {
        // ignore
      }
    }
  }

  private byte[] createValidDek() {
    byte[] dek = new byte[32];
    Arrays.fill(dek, (byte) 0x42);
    return dek;
  }

  private CachedKeyDecryptor createDecryptor() {
    return new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor, encryptionService,
        metadata);
  }

  // Constructor validation tests

  @SuppressWarnings("resource")
  public void constructorRejectNullDek() {
    try {
      new CachedKeyDecryptor(null, TEST_EDEK, executor, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("DEK must be exactly 32 bytes"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectWrongSizeDek() {
    byte[] shortDek = new byte[16];
    try {
      new CachedKeyDecryptor(shortDek, TEST_EDEK, executor, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("DEK must be exactly 32 bytes"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullEdek() {
    try {
      new CachedKeyDecryptor(createValidDek(), null, executor, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("EDEK must not be null or empty"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectEmptyEdek() {
    try {
      new CachedKeyDecryptor(createValidDek(), "", executor, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("EDEK must not be null or empty"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullExecutor() {
    try {
      new CachedKeyDecryptor(createValidDek(), TEST_EDEK, null, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("encryptionExecutor must not be null"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullEncryptionService() {
    try {
      new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor, null, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("requestService must not be null"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullMetadata() {
    try {
      new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor, encryptionService, null);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("metadata must not be null"));
    }
  }

  // Getter tests

  public void getEdekReturnsCorrectValue() {
    CachedKeyDecryptor decryptor = createDecryptor();
    assertEquals(decryptor.getEdek(), TEST_EDEK);
    decryptor.close();
  }

  public void isClosedReturnsFalseInitially() {
    CachedKeyDecryptor decryptor = createDecryptor();
    assertFalse(decryptor.isClosed());
    decryptor.close();
  }

  public void isClosedReturnsTrueAfterClose() {
    CachedKeyDecryptor decryptor = createDecryptor();
    decryptor.close();
    assertTrue(decryptor.isClosed());
  }

  // Close tests

  public void closeIsIdempotent() {
    CachedKeyDecryptor decryptor = createDecryptor();
    decryptor.close();
    assertTrue(decryptor.isClosed());
    // Should not throw
    decryptor.close();
    decryptor.close();
    assertTrue(decryptor.isClosed());
  }

  // Operation count tests

  public void operationCountStartsAtZero() {
    CachedKeyDecryptor decryptor = createDecryptor();
    assertEquals(decryptor.getOperationCount(), 0);
    decryptor.close();
  }

  // Decrypt validation tests

  public void decryptFailsWhenClosed() {
    CachedKeyDecryptor decryptor = createDecryptor();
    decryptor.close();

    EncryptedDocument encDoc = new EncryptedDocument(java.util.Collections.emptyMap(), TEST_EDEK);

    try {
      decryptor.decrypt(encDoc, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKeyDecryptor has been closed"));
    }
  }

  public void decryptFailsWhenEdekMismatch() {
    CachedKeyDecryptor decryptor = createDecryptor();

    EncryptedDocument encDoc =
        new EncryptedDocument(java.util.Collections.emptyMap(), DIFFERENT_EDEK);

    try {
      decryptor.decrypt(encDoc, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("EDEK does not match"));
    } finally {
      decryptor.close();
    }
  }

  // DecryptStream validation tests

  public void decryptStreamFailsWhenClosed() {
    CachedKeyDecryptor decryptor = createDecryptor();
    decryptor.close();

    ByteArrayInputStream input = new ByteArrayInputStream(new byte[0]);
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    try {
      decryptor.decryptStream(TEST_EDEK, input, output, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKeyDecryptor has been closed"));
    }
  }

  public void decryptStreamFailsWhenEdekMismatch() {
    CachedKeyDecryptor decryptor = createDecryptor();

    ByteArrayInputStream input = new ByteArrayInputStream(new byte[0]);
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    try {
      decryptor.decryptStream(DIFFERENT_EDEK, input, output, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("EDEK does not match"));
    } finally {
      decryptor.close();
    }
  }

  // decryptBatch validation tests

  public void decryptBatchFailsWhenClosed() {
    CachedKeyDecryptor decryptor = createDecryptor();
    decryptor.close();

    Map<String, EncryptedDocument> docs = new HashMap<>();
    docs.put("doc1", new EncryptedDocument(java.util.Collections.emptyMap(), TEST_EDEK));

    try {
      decryptor.decryptBatch(docs, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKeyDecryptor has been closed"));
    }
  }

  public void decryptBatchEdekMismatchGoesToFailures() {
    CachedKeyDecryptor decryptor = createDecryptor();

    Map<String, EncryptedDocument> docs = new HashMap<>();
    docs.put("matching", new EncryptedDocument(java.util.Collections.emptyMap(), TEST_EDEK));
    docs.put("mismatched", new EncryptedDocument(java.util.Collections.emptyMap(), DIFFERENT_EDEK));

    BatchResult<PlaintextDocument> result = decryptor.decryptBatch(docs, metadata).join();

    // The matching doc with empty fields should succeed (no fields to decrypt)
    assertTrue(result.getSuccesses().containsKey("matching"));
    // The mismatched doc should be in failures
    assertTrue(result.getFailures().containsKey("mismatched"));
    assertTrue(
        result.getFailures().get("mismatched").getMessage().contains("EDEK does not match"));
    // The matching doc should NOT be in failures
    assertFalse(result.getFailures().containsKey("matching"));

    decryptor.close();
  }

  // DEK copying test

  public void constructorCopiesDekToPreventExternalModification() throws Exception {
    byte[] originalDek = createValidDek();
    CachedKeyDecryptor decryptor =
        new CachedKeyDecryptor(originalDek, TEST_EDEK, executor, encryptionService, metadata);

    // Modify the original array
    Arrays.fill(originalDek, (byte) 0x00);

    // Use reflection to verify internal DEK still has original values
    Field dekField = CachedKeyDecryptor.class.getDeclaredField("dek");
    dekField.setAccessible(true);
    byte[] internalDek = (byte[]) dekField.get(decryptor);

    // Internal DEK should still be 0x42, not 0x00
    for (byte b : internalDek) {
      assertEquals(b, (byte) 0x42, "Internal DEK should not be affected by external modification");
    }

    decryptor.close();
  }
}
