package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.function.ToIntFunction;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;

/**
 * Holds a cached DEK (Document Encryption Key) for repeated decrypt operations without making
 * additional TSP unwrap calls. The DEK is securely zeroed when close() is called.
 *
 * <p>
 * This class is thread-safe and can be used concurrently for multiple decrypt operations. Once
 * closed, all decrypt operations will fail.
 *
 * <p>
 * <b>Expiration:</b> This decryptor automatically expires after a short time period. Caching a DEK
 * for long-term use is not supported as it would undermine the security benefits of key wrapping.
 * The decryptor is intended for short-lived batch operations where multiple documents sharing the
 * same EDEK need to be decrypted in quick succession. Use {@link #isExpired()} to check expiration
 * status.
 *
 * <p>
 * Instances are created via {@link TenantSecurityClient#createCachedDecryptor} or
 * {@link TenantSecurityClient#withCachedDecryptor}. See those methods for usage examples.
 *
 * @see TenantSecurityClient#createCachedDecryptor(String, DocumentMetadata)
 * @see TenantSecurityClient#withCachedDecryptor(String, DocumentMetadata,
 *      java.util.function.Function)
 */
public final class CachedKeyDecryptor implements DocumentDecryptor, Closeable {

  // Maximum time the decryptor can be used before it expires
  private static final Duration TIMEOUT = Duration.ofMinutes(1);

  // The cached DEK bytes - zeroed on close()
  private final byte[] dek;

  // The EDEK that was used to derive the DEK - used for validation
  private final String edek;

  // Executor for async field decryption operations
  private final ExecutorService encryptionExecutor;

  // For reporting operations on close
  private final TenantSecurityRequest requestService;
  private final DocumentMetadata metadata;

  // Flag to track if close() has been called
  private final AtomicBoolean closed = new AtomicBoolean(false);

  // When this decryptor was created - used for timeout enforcement
  private final Instant createdAt;

  // Count of successful decrypt operations performed
  private final AtomicInteger operationCount = new AtomicInteger(0);

  /**
   * Package-private constructor. Use TenantSecurityClient.createCachedDecryptor() to create
   * instances.
   *
   * @param dek The unwrapped document encryption key bytes (will be copied)
   * @param edek The encrypted document encryption key string
   * @param encryptionExecutor Executor for async decryption operations
   * @param requestService TSP request service for reporting operations on close
   * @param metadata Document metadata for reporting operations on close
   */
  CachedKeyDecryptor(byte[] dek, String edek, ExecutorService encryptionExecutor,
      TenantSecurityRequest requestService, DocumentMetadata metadata) {
    if (dek == null || dek.length != 32) {
      throw new IllegalArgumentException("DEK must be exactly 32 bytes");
    }
    if (edek == null || edek.isEmpty()) {
      throw new IllegalArgumentException("EDEK must not be null or empty");
    }
    if (encryptionExecutor == null) {
      throw new IllegalArgumentException("encryptionExecutor must not be null");
    }
    if (requestService == null) {
      throw new IllegalArgumentException("requestService must not be null");
    }
    if (metadata == null) {
      throw new IllegalArgumentException("metadata must not be null");
    }
    // Copy DEK to prevent external modification
    this.dek = Arrays.copyOf(dek, dek.length);
    this.edek = edek;
    this.encryptionExecutor = encryptionExecutor;
    this.requestService = requestService;
    this.metadata = metadata;
    this.createdAt = Instant.now();
  }

  /**
   * Get the EDEK associated with this cached decryptor. Useful for verifying which documents can be
   * decrypted with this instance.
   *
   * @return The EDEK string
   */
  public String getEdek() {
    return edek;
  }

  /**
   * Check if this decryptor has been closed.
   *
   * @return true if close() has been called
   */
  public boolean isClosed() {
    return closed.get();
  }

  /**
   * Check if this decryptor has expired due to timeout.
   *
   * @return true if the timeout has elapsed since creation
   */
  public boolean isExpired() {
    return Duration.between(createdAt, Instant.now()).compareTo(TIMEOUT) > 0;
  }

  /**
   * Get the number of successful decrypt operations performed with this decryptor.
   *
   * @return The operation count
   */
  public int getOperationCount() {
    return operationCount.get();
  }

  /**
   * Guard an operation with usability checks and operation counting. Verifies the decryptor is not
   * closed or expired before running the operation, and increments the operation count on success.
   *
   * @param operation The operation to perform
   * @param countOps Extracts the number of successful operations from the result
   */
  private <T> CompletableFuture<T> executeAndIncrement(Supplier<CompletableFuture<T>> operation,
      ToIntFunction<T> countOps) {
    if (closed.get()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED, "CachedKeyDecryptor has been closed"));
    }
    if (isExpired()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED, "CachedKeyDecryptor has expired"));
    }
    return operation.get().thenApply(result -> {
      operationCount.addAndGet(countOps.applyAsInt(result));
      return result;
    });
  }

  private CompletableFuture<PlaintextDocument> validateEdekAndDecrypt(
      EncryptedDocument encryptedDocument) {
    if (!edek.equals(encryptedDocument.getEdek())) {
      return CompletableFuture.failedFuture(
          new TscException(TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED,
              "EncryptedDocument EDEK does not match the cached EDEK. "
                  + "This decryptor can only decrypt documents with matching EDEKs."));
    }
    return DocumentCryptoOps.decryptFields(encryptedDocument.getEncryptedFields(), dek,
        encryptedDocument.getEdek(), encryptionExecutor);
  }

  @Override
  public CompletableFuture<PlaintextDocument> decrypt(EncryptedDocument encryptedDocument,
      DocumentMetadata metadata) {
    return executeAndIncrement(() -> validateEdekAndDecrypt(encryptedDocument), result -> 1);
  }

  @Override
  public CompletableFuture<Void> decryptStream(String edek, InputStream input, OutputStream output,
      DocumentMetadata metadata) {
    return executeAndIncrement(() -> {
      if (!this.edek.equals(edek)) {
        return CompletableFuture
            .<Void>failedFuture(new TscException(TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED,
                "Provided EDEK does not match the cached EDEK. "
                    + "This decryptor can only decrypt documents with matching EDEKs."));
      }
      return CompletableFuture
          .supplyAsync(() -> CryptoUtils.decryptStreamInternal(this.dek, input, output).join(),
              encryptionExecutor);
    }, result -> 1);
  }

  @Override
  public CompletableFuture<BatchResult<PlaintextDocument>> decryptBatch(
      Map<String, EncryptedDocument> encryptedDocuments, DocumentMetadata metadata) {
    return executeAndIncrement(() -> {
      ConcurrentMap<String, CompletableFuture<PlaintextDocument>> ops = new ConcurrentHashMap<>();
      ConcurrentMap<String, TenantSecurityException> edekMismatches = new ConcurrentHashMap<>();

      encryptedDocuments.forEach((id, encDoc) -> {
        if (!edek.equals(encDoc.getEdek())) {
          edekMismatches.put(id,
              new TscException(TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED,
                  "EncryptedDocument EDEK does not match the cached EDEK. "
                      + "This decryptor can only decrypt documents with matching EDEKs."));
        } else {
          ops.put(id, DocumentCryptoOps.decryptFields(encDoc.getEncryptedFields(), dek,
              encDoc.getEdek(), encryptionExecutor));
        }
      });

      return CompletableFuture.supplyAsync(() -> {
        BatchResult<PlaintextDocument> result = DocumentCryptoOps.cryptoOperationToBatchResult(ops,
            TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED);
        ConcurrentMap<String, TenantSecurityException> allFailures =
            new ConcurrentHashMap<>(result.getFailures());
        allFailures.putAll(edekMismatches);
        return new BatchResult<>(result.getSuccesses(), allFailures);
      });
    }, result -> result.getSuccesses().size());
  }

  /**
   * Securely zero the DEK bytes, report operations to the TSP, and mark this decryptor as closed.
   * After calling close(), all decrypt operations will fail.
   *
   * <p>
   * This method is idempotent - calling it multiple times has no additional effect.
   */
  @Override
  public void close() {
    if (closed.compareAndSet(false, true)) {
      // Zero out the DEK bytes for security
      Arrays.fill(dek, (byte) 0);
      // Report operations to TSP
      int count = operationCount.get();
      if (count > 0) {
        requestService.reportOperations(metadata, edek, 0, count);
      }
    }
  }
}
