package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

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

  // Flag to track if close() has been called
  private final AtomicBoolean closed = new AtomicBoolean(false);

  // When this decryptor was created - used for timeout enforcement
  private final Instant createdAt;

  /**
   * Package-private constructor. Use TenantSecurityClient.createCachedDecryptor() to create
   * instances.
   *
   * @param dek The unwrapped document encryption key bytes (will be copied)
   * @param edek The encrypted document encryption key string
   * @param encryptionExecutor Executor for async decryption operations
   */
  CachedKeyDecryptor(byte[] dek, String edek, ExecutorService encryptionExecutor) {
    if (dek == null || dek.length != 32) {
      throw new IllegalArgumentException("DEK must be exactly 32 bytes");
    }
    if (edek == null || edek.isEmpty()) {
      throw new IllegalArgumentException("EDEK must not be null or empty");
    }
    if (encryptionExecutor == null) {
      throw new IllegalArgumentException("encryptionExecutor must not be null");
    }
    // Copy DEK to prevent external modification
    this.dek = Arrays.copyOf(dek, dek.length);
    this.edek = edek;
    this.encryptionExecutor = encryptionExecutor;
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
   * Decrypt the provided EncryptedDocument using the cached DEK.
   *
   * <p>
   * The document's EDEK must match the EDEK used to create this decryptor, otherwise an error is
   * returned.
   *
   * @param encryptedDocument Document to decrypt
   * @param metadata Metadata about the document being decrypted (used for audit/logging)
   * @return CompletableFuture resolving to PlaintextDocument
   */
  @Override
  public CompletableFuture<PlaintextDocument> decrypt(EncryptedDocument encryptedDocument,
      DocumentMetadata metadata) {
    // Check if closed or expired
    if (closed.get()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED, "CachedKeyDecryptor has been closed"));
    }
    if (isExpired()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED, "CachedKeyDecryptor has expired"));
    }

    // Validate EDEK matches
    if (!edek.equals(encryptedDocument.getEdek())) {
      return CompletableFuture
          .failedFuture(new TscException(TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED,
              "EncryptedDocument EDEK does not match the cached EDEK. "
                  + "This decryptor can only decrypt documents with matching EDEKs."));
    }

    return decryptFields(encryptedDocument.getEncryptedFields(), encryptedDocument.getEdek());
  }

  /**
   * Decrypt a stream using the cached DEK.
   *
   * <p>
   * The provided EDEK must match the EDEK used to create this decryptor, otherwise an error is
   * returned.
   *
   * @param edek Encrypted document encryption key - must match this decryptor's EDEK
   * @param input A stream representing the encrypted document
   * @param output An output stream to write the decrypted document to
   * @param metadata Metadata about the document being decrypted
   * @return Future which will complete when input has been decrypted
   */
  @Override
  public CompletableFuture<Void> decryptStream(String edek, InputStream input, OutputStream output,
      DocumentMetadata metadata) {
    // Check if closed or expired
    if (closed.get()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED, "CachedKeyDecryptor has been closed"));
    }
    if (isExpired()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED, "CachedKeyDecryptor has expired"));
    }

    // Validate EDEK matches
    if (!this.edek.equals(edek)) {
      return CompletableFuture
          .failedFuture(new TscException(TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED,
              "Provided EDEK does not match the cached EDEK. "
                  + "This decryptor can only decrypt documents with matching EDEKs."));
    }

    return CompletableFuture.supplyAsync(
        () -> CryptoUtils.decryptStreamInternal(dek, input, output).join(), encryptionExecutor);
  }

  /**
   * Decrypt all fields in the document using the cached DEK. Pattern follows
   * TenantSecurityClient.decryptFields().
   */
  private CompletableFuture<PlaintextDocument> decryptFields(Map<String, byte[]> document,
      String documentEdek) {
    // Check closed/expired state again before starting decryption
    if (closed.get()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED, "CachedKeyDecryptor has been closed"));
    }
    if (isExpired()) {
      return CompletableFuture.failedFuture(new TscException(
          TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED, "CachedKeyDecryptor has expired"));
    }

    // Parallel decrypt each field
    Map<String, CompletableFuture<byte[]>> decryptOps = document.entrySet().stream()
        .collect(Collectors.toMap(Map.Entry::getKey,
            entry -> CompletableFuture.supplyAsync(
                () -> CryptoUtils.decryptDocument(entry.getValue(), dek).join(),
                encryptionExecutor)));

    // Join all futures and build result
    return CompletableFutures.tryCatchNonFatal(() -> {
      Map<String, byte[]> decryptedBytes = decryptOps.entrySet().stream()
          .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().join()));
      return new PlaintextDocument(decryptedBytes, documentEdek);
    });
  }

  /**
   * Securely zero the DEK bytes and mark this decryptor as closed. After calling close(), all
   * decrypt operations will fail.
   *
   * <p>
   * This method is idempotent - calling it multiple times has no additional effect.
   */
  @Override
  public void close() {
    if (closed.compareAndSet(false, true)) {
      // Zero out the DEK bytes for security
      Arrays.fill(dek, (byte) 0);
    }
  }
}
