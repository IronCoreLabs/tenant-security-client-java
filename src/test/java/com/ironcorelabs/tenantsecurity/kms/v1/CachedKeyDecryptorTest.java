package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.util.Arrays;
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
  private static final String TEST_EDEK = "test-edek-base64-string";
  private static final String DIFFERENT_EDEK = "different-edek-base64-string";
  private DocumentMetadata metadata =
      new DocumentMetadata("tenantId", "requestingUserOrServiceId", "dataLabel");

  @BeforeClass
  public void setup() {
    executor = Executors.newFixedThreadPool(2);
  }

  @AfterClass
  public void teardown() {
    if (executor != null) {
      executor.shutdown();
    }
  }

  private byte[] createValidDek() {
    byte[] dek = new byte[32];
    Arrays.fill(dek, (byte) 0x42);
    return dek;
  }

  // Constructor validation tests

  public void constructorRejectNullDek() {
    try {
      new CachedKeyDecryptor(null, TEST_EDEK, executor);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("DEK must be exactly 32 bytes"));
    }
  }

  public void constructorRejectWrongSizeDek() {
    byte[] shortDek = new byte[16];
    try {
      new CachedKeyDecryptor(shortDek, TEST_EDEK, executor);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("DEK must be exactly 32 bytes"));
    }
  }

  public void constructorRejectNullEdek() {
    try {
      new CachedKeyDecryptor(createValidDek(), null, executor);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("EDEK must not be null or empty"));
    }
  }

  public void constructorRejectEmptyEdek() {
    try {
      new CachedKeyDecryptor(createValidDek(), "", executor);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("EDEK must not be null or empty"));
    }
  }

  public void constructorRejectNullExecutor() {
    try {
      new CachedKeyDecryptor(createValidDek(), TEST_EDEK, null);
      fail("Should have thrown IllegalArgumentException");
    } catch (IllegalArgumentException e) {
      assertTrue(e.getMessage().contains("encryptionExecutor must not be null"));
    }
  }

  // Getter tests

  public void getEdekReturnsCorrectValue() {
    CachedKeyDecryptor decryptor = new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor);
    assertEquals(decryptor.getEdek(), TEST_EDEK);
    decryptor.close();
  }

  public void isClosedReturnsFalseInitially() {
    CachedKeyDecryptor decryptor = new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor);
    assertFalse(decryptor.isClosed());
    decryptor.close();
  }

  public void isClosedReturnsTrueAfterClose() {
    CachedKeyDecryptor decryptor = new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor);
    decryptor.close();
    assertTrue(decryptor.isClosed());
  }

  // Close tests

  public void closeIsIdempotent() {
    CachedKeyDecryptor decryptor = new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor);
    decryptor.close();
    assertTrue(decryptor.isClosed());
    // Should not throw
    decryptor.close();
    decryptor.close();
    assertTrue(decryptor.isClosed());
  }

  // Decrypt validation tests

  public void decryptFailsWhenClosed() {
    CachedKeyDecryptor decryptor = new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor);
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
    CachedKeyDecryptor decryptor = new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor);

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
    CachedKeyDecryptor decryptor = new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor);
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
    CachedKeyDecryptor decryptor = new CachedKeyDecryptor(createValidDek(), TEST_EDEK, executor);

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

  // DEK copying test

  public void constructorCopiesDekToPreventExternalModification() throws Exception {
    byte[] originalDek = createValidDek();
    CachedKeyDecryptor decryptor = new CachedKeyDecryptor(originalDek, TEST_EDEK, executor);

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
