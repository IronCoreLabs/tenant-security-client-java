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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

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
   * Check if this encryptor is usable (not closed and not expired). Returns a failed future if not,
   * or a completed future if usable.
   */
  private CompletableFuture<Void> checkUsable() {
    if (closed.get()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED, "CachedKeyEncryptor has been closed"));
    }
    if (isExpired()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED, "CachedKeyEncryptor has expired"));
    }
    return CompletableFuture.completedFuture(null);
  }

  /**
   * Encrypt the provided document fields using the cached DEK.
   *
   * @param document Map of field names to plaintext bytes to encrypt.
   * @param metadata Metadata about the document being encrypted.
   * @return CompletableFuture resolving to EncryptedDocument with encrypted field bytes and EDEK.
   */
  @Override
  public CompletableFuture<EncryptedDocument> encrypt(Map<String, byte[]> document,
      DocumentMetadata metadata) {
    return checkUsable()
        .thenCompose(unused -> encryptFields(document, metadata).thenApply(result -> {
          operationCount.incrementAndGet();
          return result;
        }));
  }

  /**
   * Encrypt a stream of bytes using the cached DEK.
   *
   * @param input The input stream of plaintext bytes to encrypt.
   * @param output The output stream to write encrypted bytes to.
   * @param metadata Metadata about the document being encrypted.
   * @return CompletableFuture resolving to StreamingResponse containing the EDEK.
   */
  @Override
  public CompletableFuture<StreamingResponse> encryptStream(InputStream input, OutputStream output,
      DocumentMetadata metadata) {
    return checkUsable().thenCompose(unused -> CompletableFuture.supplyAsync(
        () -> CryptoUtils.encryptStreamInternal(dek, metadata, input, output, secureRandom).join(),
        encryptionExecutor).thenApply(v -> {
          operationCount.incrementAndGet();
          return new StreamingResponse(edek);
        }));
  }

  // Caller must call checkUsable() before invoking this method.
  private CompletableFuture<EncryptedDocument> encryptFields(Map<String, byte[]> document,
      DocumentMetadata metadata) {
    // Parallel encrypt each field
    Map<String, CompletableFuture<byte[]>> encryptOps = document.entrySet().stream()
        .collect(Collectors.toMap(Map.Entry::getKey, entry -> CompletableFuture.supplyAsync(
            () -> CryptoUtils.encryptBytes(entry.getValue(), metadata, dek, secureRandom).join(),
            encryptionExecutor)));

    // Join all futures and build result
    return CompletableFutures.tryCatchNonFatal(() -> {
      Map<String, byte[]> encryptedBytes = encryptOps.entrySet().stream()
          .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().join()));
      return new EncryptedDocument(encryptedBytes, edek);
    });
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
