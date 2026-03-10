package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.security.SecureRandom;
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
public class CachedKeyTest {

  private ExecutorService executor;
  private SecureRandom secureRandom;
  private TenantSecurityRequest encryptionService;
  private static final String TEST_EDEK = "test-edek-base64-string";
  private static final String DIFFERENT_EDEK = "different-edek-base64-string";
  private DocumentMetadata metadata =
      new DocumentMetadata("tenantId", "requestingUserOrServiceId", "dataLabel");

  @BeforeClass
  public void setup() {
    executor = Executors.newFixedThreadPool(2);
    secureRandom = new SecureRandom();
    // This endpoint doesn't exist, so we won't call `close` on the cached key to avoid the
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

  private CachedKey createCachedKey() {
    return new CachedKey(createValidDek(), TEST_EDEK, executor, secureRandom, encryptionService,
        metadata);
  }

  // Constructor validation tests

  @SuppressWarnings("resource")
  public void constructorRejectNullDek() {
    try {
      new CachedKey(null, TEST_EDEK, executor, secureRandom, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("DEK must be exactly 32 bytes"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectWrongSizeDek() {
    byte[] shortDek = new byte[16];
    try {
      new CachedKey(shortDek, TEST_EDEK, executor, secureRandom, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("DEK must be exactly 32 bytes"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullEdek() {
    try {
      new CachedKey(createValidDek(), null, executor, secureRandom, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("EDEK must not be null or empty"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectEmptyEdek() {
    try {
      new CachedKey(createValidDek(), "", executor, secureRandom, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("EDEK must not be null or empty"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullExecutor() {
    try {
      new CachedKey(createValidDek(), TEST_EDEK, null, secureRandom, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("encryptionExecutor must not be null"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullSecureRandom() {
    try {
      new CachedKey(createValidDek(), TEST_EDEK, executor, null, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("secureRandom must not be null"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullEncryptionService() {
    try {
      new CachedKey(createValidDek(), TEST_EDEK, executor, secureRandom, null, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("requestService must not be null"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullMetadata() {
    try {
      new CachedKey(createValidDek(), TEST_EDEK, executor, secureRandom, encryptionService, null);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("metadata must not be null"));
    }
  }

  // Getter tests

  public void getEdekReturnsCorrectValue() {
    CachedKey cachedKey = createCachedKey();
    assertEquals(cachedKey.getEdek(), TEST_EDEK);
    cachedKey.close();
  }

  public void isClosedReturnsFalseInitially() {
    CachedKey cachedKey = createCachedKey();
    assertFalse(cachedKey.isClosed());
    cachedKey.close();
  }

  public void isClosedReturnsTrueAfterClose() {
    CachedKey cachedKey = createCachedKey();
    cachedKey.close();
    assertTrue(cachedKey.isClosed());
  }

  // Close tests

  public void closeIsIdempotent() {
    CachedKey cachedKey = createCachedKey();
    cachedKey.close();
    assertTrue(cachedKey.isClosed());
    // Should not throw
    cachedKey.close();
    cachedKey.close();
    assertTrue(cachedKey.isClosed());
  }

  // Operation count tests

  public void operationCountStartsAtZero() {
    CachedKey cachedKey = createCachedKey();
    assertEquals(cachedKey.getOperationCount(), 0);
    assertEquals(cachedKey.getEncryptCount(), 0);
    assertEquals(cachedKey.getDecryptCount(), 0);
    cachedKey.close();
  }

  // Encrypt validation tests

  public void encryptFailsWhenClosed() {
    CachedKey cachedKey = createCachedKey();
    cachedKey.close();

    try {
      cachedKey.encrypt(java.util.Collections.emptyMap(), metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKey has been closed"));
    }
  }

  public void encryptStreamFailsWhenClosed() {
    CachedKey cachedKey = createCachedKey();
    cachedKey.close();

    ByteArrayInputStream input = new ByteArrayInputStream(new byte[0]);
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    try {
      cachedKey.encryptStream(input, output, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKey has been closed"));
    }
  }

  public void encryptBatchFailsWhenClosed() {
    CachedKey cachedKey = createCachedKey();
    cachedKey.close();

    Map<String, Map<String, byte[]>> docs = new HashMap<>();
    docs.put("doc1", java.util.Collections.singletonMap("field", new byte[] {1, 2, 3}));

    try {
      cachedKey.encryptBatch(docs, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKey has been closed"));
    }
  }

  // Decrypt validation tests

  public void decryptFailsWhenClosed() {
    CachedKey cachedKey = createCachedKey();
    cachedKey.close();

    EncryptedDocument encDoc = new EncryptedDocument(java.util.Collections.emptyMap(), TEST_EDEK);

    try {
      cachedKey.decrypt(encDoc, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKey has been closed"));
    }
  }

  public void decryptFailsWhenEdekMismatch() {
    CachedKey cachedKey = createCachedKey();

    EncryptedDocument encDoc =
        new EncryptedDocument(java.util.Collections.emptyMap(), DIFFERENT_EDEK);

    try {
      cachedKey.decrypt(encDoc, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("EDEK does not match"));
    } finally {
      cachedKey.close();
    }
  }

  // DecryptStream validation tests

  public void decryptStreamFailsWhenClosed() {
    CachedKey cachedKey = createCachedKey();
    cachedKey.close();

    ByteArrayInputStream input = new ByteArrayInputStream(new byte[0]);
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    try {
      cachedKey.decryptStream(TEST_EDEK, input, output, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKey has been closed"));
    }
  }

  public void decryptStreamFailsWhenEdekMismatch() {
    CachedKey cachedKey = createCachedKey();

    ByteArrayInputStream input = new ByteArrayInputStream(new byte[0]);
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    try {
      cachedKey.decryptStream(DIFFERENT_EDEK, input, output, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("EDEK does not match"));
    } finally {
      cachedKey.close();
    }
  }

  // decryptBatch validation tests

  public void decryptBatchFailsWhenClosed() {
    CachedKey cachedKey = createCachedKey();
    cachedKey.close();

    Map<String, EncryptedDocument> docs = new HashMap<>();
    docs.put("doc1", new EncryptedDocument(java.util.Collections.emptyMap(), TEST_EDEK));

    try {
      cachedKey.decryptBatch(docs, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKey has been closed"));
    }
  }

  public void decryptBatchEdekMismatchGoesToFailures() {
    CachedKey cachedKey = createCachedKey();

    Map<String, EncryptedDocument> docs = new HashMap<>();
    docs.put("matching", new EncryptedDocument(java.util.Collections.emptyMap(), TEST_EDEK));
    docs.put("mismatched", new EncryptedDocument(java.util.Collections.emptyMap(), DIFFERENT_EDEK));

    BatchResult<PlaintextDocument> result = cachedKey.decryptBatch(docs, metadata).join();

    // The matching doc with empty fields should succeed (no fields to decrypt)
    assertTrue(result.getSuccesses().containsKey("matching"));
    // The mismatched doc should be in failures
    assertTrue(result.getFailures().containsKey("mismatched"));
    assertTrue(
        result.getFailures().get("mismatched").getMessage().contains("EDEK does not match"));
    // The matching doc should NOT be in failures
    assertFalse(result.getFailures().containsKey("matching"));

    cachedKey.close();
  }

  // DEK copying test

  public void constructorCopiesDekToPreventExternalModification() throws Exception {
    byte[] originalDek = createValidDek();
    CachedKey cachedKey = new CachedKey(originalDek, TEST_EDEK, executor, secureRandom,
        encryptionService, metadata);

    // Modify the original array
    Arrays.fill(originalDek, (byte) 0x00);

    // Use reflection to verify internal DEK still has original values
    Field dekField = CachedKey.class.getDeclaredField("dek");
    dekField.setAccessible(true);
    byte[] internalDek = (byte[]) dekField.get(cachedKey);

    // Internal DEK should still be 0x42, not 0x00
    for (byte b : internalDek) {
      assertEquals(b, (byte) 0x42, "Internal DEK should not be affected by external modification");
    }

    cachedKey.close();
  }
}
