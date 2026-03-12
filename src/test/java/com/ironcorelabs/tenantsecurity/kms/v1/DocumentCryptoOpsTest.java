package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertTrue;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.testng.annotations.Test;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;

@Test(groups = {"unit"})
public class DocumentCryptoOpsTest {

  public void cryptoOperationToBatchResultAllSuccess() {
    ConcurrentMap<String, CompletableFuture<String>> ops = new ConcurrentHashMap<>();
    ops.put("a", CompletableFuture.completedFuture("resultA"));
    ops.put("b", CompletableFuture.completedFuture("resultB"));

    BatchResult<String> result = DocumentCryptoOps.cryptoOperationToBatchResult(ops,
        TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED);

    assertEquals(result.getSuccesses().size(), 2);
    assertEquals(result.getSuccesses().get("a"), "resultA");
    assertEquals(result.getSuccesses().get("b"), "resultB");
    assertFalse(result.hasFailures());
  }

  public void cryptoOperationToBatchResultAllFailure() {
    ConcurrentMap<String, CompletableFuture<String>> ops = new ConcurrentHashMap<>();
    ops.put("a", CompletableFuture.failedFuture(new RuntimeException("fail A")));
    ops.put("b", CompletableFuture.failedFuture(new RuntimeException("fail B")));

    BatchResult<String> result = DocumentCryptoOps.cryptoOperationToBatchResult(ops,
        TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED);

    assertFalse(result.hasSuccesses());
    assertEquals(result.getFailures().size(), 2);
    assertTrue(result.getFailures().get("a") instanceof TscException);
    assertTrue(result.getFailures().get("b") instanceof TscException);
  }

  public void cryptoOperationToBatchResultMixed() {
    ConcurrentMap<String, CompletableFuture<String>> ops = new ConcurrentHashMap<>();
    ops.put("good", CompletableFuture.completedFuture("value"));
    ops.put("bad", CompletableFuture.failedFuture(new RuntimeException("oops")));

    BatchResult<String> result = DocumentCryptoOps.cryptoOperationToBatchResult(ops,
        TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED);

    assertTrue(result.hasSuccesses());
    assertTrue(result.hasFailures());
    assertEquals(result.getSuccesses().size(), 1);
    assertEquals(result.getSuccesses().get("good"), "value");
    assertEquals(result.getFailures().size(), 1);
    assertTrue(result.getFailures().containsKey("bad"));
  }

  public void cryptoOperationToBatchResultEmpty() {
    ConcurrentMap<String, CompletableFuture<String>> ops = new ConcurrentHashMap<>();

    BatchResult<String> result = DocumentCryptoOps.cryptoOperationToBatchResult(ops,
        TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED);

    assertFalse(result.hasSuccesses());
    assertFalse(result.hasFailures());
  }
}
