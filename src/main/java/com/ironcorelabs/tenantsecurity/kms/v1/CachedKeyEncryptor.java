package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
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
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;

/**
 * Holds a cached DEK (Document Encryption Key) for repeated encrypt operations without making
 * additional TSP wrap calls. All documents encrypted with this instance will share the same
 * DEK/EDEK pair. The DEK is securely zeroed when close() is called.
 *
 * <p>
 * This class is thread-safe and can be used concurrently for multiple encrypt operations. Once
 * closed, all encrypt operations will fail.
 *
 * <p>
 * <b>Expiration:</b> This encryptor automatically expires after a short time period. Caching a DEK
 * for long-term use is not supported as it would undermine the security benefits of key wrapping.
 * The encryptor is intended for short-lived batch operations where multiple documents need to be
 * encrypted in quick succession with the same key. Use {@link #isExpired()} to check expiration
 * status.
 *
 * <p>
 * Instances are created via {@link TenantSecurityClient#createCachedEncryptor} or
 * {@link TenantSecurityClient#withCachedEncryptor}. See those methods for usage examples.
 *
 * @see TenantSecurityClient#createCachedEncryptor(DocumentMetadata)
 * @see TenantSecurityClient#withCachedEncryptor(DocumentMetadata, java.util.function.Function)
 */
public final class CachedKeyEncryptor implements DocumentEncryptor, Closeable {

  // Maximum time the encryptor can be used before it expires
  private static final Duration TIMEOUT = Duration.ofMinutes(1);

  // The cached DEK bytes - zeroed on close()
  private final byte[] dek;

  // The EDEK associated with the cached DEK
  private final String edek;

  // Executor for async field encryption operations
  private final ExecutorService encryptionExecutor;

  // Secure random for IV generation during encryption
  private final SecureRandom secureRandom;

  // For reporting operations on close
  private final TenantSecurityRequest requestService;
  private final DocumentMetadata metadata;

  // Flag to track if close() has been called
  private final AtomicBoolean closed = new AtomicBoolean(false);

  // When this encryptor was created - used for timeout enforcement
  private final Instant createdAt;

  // Count of successful encrypt operations performed
  private final AtomicInteger operationCount = new AtomicInteger(0);

  /**
   * Package-private constructor. Use TenantSecurityClient.createCachedEncryptor() to create
   * instances.
   *
   * @param dek The document encryption key bytes (will be copied)
   * @param edek The encrypted document encryption key string
   * @param encryptionExecutor Executor for async encryption operations
   * @param secureRandom Secure random for IV generation
   * @param requestService TSP request service for reporting operations on close
   * @param metadata Document metadata for reporting operations on close
   */
  CachedKeyEncryptor(byte[] dek, String edek, ExecutorService encryptionExecutor,
      SecureRandom secureRandom, TenantSecurityRequest requestService, DocumentMetadata metadata) {
    if (dek == null || dek.length != 32) {
      throw new IllegalArgumentException("DEK must be exactly 32 bytes");
    }
    if (edek == null || edek.isEmpty()) {
      throw new IllegalArgumentException("EDEK must not be null or empty");
    }
    if (encryptionExecutor == null) {
      throw new IllegalArgumentException("encryptionExecutor must not be null");
    }
    if (secureRandom == null) {
      throw new IllegalArgumentException("secureRandom must not be null");
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
    this.secureRandom = secureRandom;
    this.requestService = requestService;
    this.metadata = metadata;
    this.createdAt = Instant.now();
  }

  /**
   * Get the EDEK associated with this cached encryptor.
   *
   * @return The EDEK string
   */
  public String getEdek() {
    return edek;
  }

  /**
   * Check if this encryptor has been closed.
   *
   * @return true if close() has been called
   */
  public boolean isClosed() {
    return closed.get();
  }

  /**
   * Check if this encryptor has expired due to timeout.
   *
   * @return true if the timeout has elapsed since creation
   */
  public boolean isExpired() {
    return Duration.between(createdAt, Instant.now()).compareTo(TIMEOUT) > 0;
  }

  /**
   * Get the number of successful encrypt operations performed with this encryptor.
   *
   * @return The operation count
   */
  public int getOperationCount() {
    return operationCount.get();
  }

  /**
   * Guard an operation with usability checks and operation counting. Verifies the encryptor is not
   * closed or expired before running the operation, and increments the operation count on success.
   *
   * @param operation The operation to perform
   * @param countOps Extracts the number of successful operations from the result
   */
  private <T> CompletableFuture<T> executeAndIncrement(Supplier<CompletableFuture<T>> operation,
      ToIntFunction<T> countOps) {
    if (closed.get()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED, "CachedKeyEncryptor has been closed"));
    }
    if (isExpired()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED, "CachedKeyEncryptor has expired"));
    }
    return operation.get().thenApply(result -> {
      operationCount.addAndGet(countOps.applyAsInt(result));
      return result;
    });
  }

  @Override
  public CompletableFuture<EncryptedDocument> encrypt(Map<String, byte[]> document,
      DocumentMetadata metadata) {
    return executeAndIncrement(
        () -> DocumentCryptoOps.encryptFields(document, metadata, dek, edek, encryptionExecutor,
            secureRandom),
        result -> 1);
  }

  @Override
  public CompletableFuture<StreamingResponse> encryptStream(InputStream input, OutputStream output,
      DocumentMetadata metadata) {
    return executeAndIncrement(
        () -> CompletableFuture.supplyAsync(
            () -> CryptoUtils.encryptStreamInternal(dek, metadata, input, output, secureRandom)
                .join(),
            encryptionExecutor).thenApply(v -> new StreamingResponse(edek)),
        result -> 1);
  }

  @Override
  public CompletableFuture<BatchResult<EncryptedDocument>> encryptBatch(
      Map<String, Map<String, byte[]>> plaintextDocuments, DocumentMetadata metadata) {
    return executeAndIncrement(() -> {
      ConcurrentMap<String, CompletableFuture<EncryptedDocument>> ops = new ConcurrentHashMap<>();
      plaintextDocuments.forEach((id, doc) -> ops.put(id,
          DocumentCryptoOps.encryptFields(doc, metadata, dek, edek, encryptionExecutor,
              secureRandom)));
      return CompletableFuture.supplyAsync(() -> DocumentCryptoOps.cryptoOperationToBatchResult(ops,
          TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED));
    }, result -> result.getSuccesses().size());
  }

  /**
   * Securely zero the DEK bytes, report operations to the TSP, and mark this encryptor as closed.
   * After calling close(), all encrypt operations will fail.
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
        requestService.reportOperations(metadata, edek, count, 0);
      }
    }
  }
}
