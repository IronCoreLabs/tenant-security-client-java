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
public class CachedKeyEncryptorTest {

  private ExecutorService executor;
  private SecureRandom secureRandom;
  private TenantSecurityRequest encryptionService;
  private static final String TEST_EDEK = "test-edek-base64-string";
  private DocumentMetadata metadata =
      new DocumentMetadata("tenantId", "requestingUserOrServiceId", "dataLabel");

  @BeforeClass
  public void setup() {
    executor = Executors.newFixedThreadPool(2);
    secureRandom = new SecureRandom();
    // This endpoint doesn't exist, so we won't call `close` on the cached encryptor to avoid the
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

  private CachedKeyEncryptor createEncryptor() {
    return new CachedKeyEncryptor(createValidDek(), TEST_EDEK, executor, secureRandom,
        encryptionService, metadata);
  }

  // Constructor validation tests

  @SuppressWarnings("resource")
  public void constructorRejectNullDek() {
    try {
      new CachedKeyEncryptor(null, TEST_EDEK, executor, secureRandom, encryptionService, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("DEK must be exactly 32 bytes"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectWrongSizeDek() {
    byte[] shortDek = new byte[16];
    try {
      new CachedKeyEncryptor(shortDek, TEST_EDEK, executor, secureRandom, encryptionService,
          metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("DEK must be exactly 32 bytes"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullEdek() {
    try {
      new CachedKeyEncryptor(createValidDek(), null, executor, secureRandom, encryptionService,
          metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("EDEK must not be null or empty"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectEmptyEdek() {
    try {
      new CachedKeyEncryptor(createValidDek(), "", executor, secureRandom, encryptionService,
          metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("EDEK must not be null or empty"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullExecutor() {
    try {
      new CachedKeyEncryptor(createValidDek(), TEST_EDEK, null, secureRandom, encryptionService,
          metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("encryptionExecutor must not be null"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullSecureRandom() {
    try {
      new CachedKeyEncryptor(createValidDek(), TEST_EDEK, executor, null, encryptionService,
          metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("secureRandom must not be null"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullEncryptionService() {
    try {
      new CachedKeyEncryptor(createValidDek(), TEST_EDEK, executor, secureRandom, null, metadata);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("requestService must not be null"));
    }
  }

  @SuppressWarnings("resource")
  public void constructorRejectNullMetadata() {
    try {
      new CachedKeyEncryptor(createValidDek(), TEST_EDEK, executor, secureRandom, encryptionService,
          null);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("metadata must not be null"));
    }
  }

  // Getter tests

  public void getEdekReturnsCorrectValue() {
    CachedKeyEncryptor encryptor = createEncryptor();
    assertEquals(encryptor.getEdek(), TEST_EDEK);
    encryptor.close();
  }

  public void isClosedReturnsFalseInitially() {
    CachedKeyEncryptor encryptor = createEncryptor();
    assertFalse(encryptor.isClosed());
    encryptor.close();
  }

  public void isClosedReturnsTrueAfterClose() {
    CachedKeyEncryptor encryptor = createEncryptor();
    encryptor.close();
    assertTrue(encryptor.isClosed());
  }

  // Close tests

  public void closeIsIdempotent() {
    CachedKeyEncryptor encryptor = createEncryptor();
    encryptor.close();
    assertTrue(encryptor.isClosed());
    // Should not throw
    encryptor.close();
    encryptor.close();
    assertTrue(encryptor.isClosed());
  }

  // Operation count tests

  public void operationCountStartsAtZero() {
    CachedKeyEncryptor encryptor = createEncryptor();
    assertEquals(encryptor.getOperationCount(), 0);
    encryptor.close();
  }

  // Encrypt validation tests

  public void encryptFailsWhenClosed() {
    CachedKeyEncryptor encryptor = createEncryptor();
    encryptor.close();

    try {
      encryptor.encrypt(java.util.Collections.emptyMap(), metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKeyEncryptor has been closed"));
    }
  }

  public void encryptStreamFailsWhenClosed() {
    CachedKeyEncryptor encryptor = createEncryptor();
    encryptor.close();

    ByteArrayInputStream input = new ByteArrayInputStream(new byte[0]);
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    try {
      encryptor.encryptStream(input, output, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKeyEncryptor has been closed"));
    }
  }

  // encryptBatch validation tests

  public void encryptBatchFailsWhenClosed() {
    CachedKeyEncryptor encryptor = createEncryptor();
    encryptor.close();

    Map<String, Map<String, byte[]>> docs = new HashMap<>();
    docs.put("doc1", java.util.Collections.singletonMap("field", new byte[] {1, 2, 3}));

    try {
      encryptor.encryptBatch(docs, metadata).join();
      fail("Should have thrown CompletionException");
    } catch (CompletionException e) {
      assertTrue(e.getCause() instanceof TscException);
      assertTrue(e.getCause().getMessage().contains("CachedKeyEncryptor has been closed"));
    }
  }

  // DEK copying test

  public void constructorCopiesDekToPreventExternalModification() throws Exception {
    byte[] originalDek = createValidDek();
    CachedKeyEncryptor encryptor = new CachedKeyEncryptor(originalDek, TEST_EDEK, executor,
        secureRandom, encryptionService, metadata);

    // Modify the original array
    Arrays.fill(originalDek, (byte) 0x00);

    // Use reflection to verify internal DEK still has original values
    Field dekField = CachedKeyEncryptor.class.getDeclaredField("dek");
    dekField.setAccessible(true);
    byte[] internalDek = (byte[]) dekField.get(encryptor);

    // Internal DEK should still be 0x42, not 0x00
    for (byte b : internalDek) {
      assertEquals(b, (byte) 0x42, "Internal DEK should not be affected by external modification");
    }

    encryptor.close();
  }
}
