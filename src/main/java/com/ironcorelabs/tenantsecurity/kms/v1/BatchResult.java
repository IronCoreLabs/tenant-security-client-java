package com.ironcorelabs.tenantsecurity.kms.v1;

import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import java.util.concurrent.ConcurrentMap;

/**
 * Holds result of a batch encrypt or decrypt operation which supports partial failure. Batch
 * operations can have both successes and failures and this class holds both fields.
 */
public final class BatchResult<T> {
  private final ConcurrentMap<String, T> documents;
  private final ConcurrentMap<String, TenantSecurityException> failures;

  public BatchResult(
      ConcurrentMap<String, T> documents, ConcurrentMap<String, TenantSecurityException> failures) {
    this.documents = documents;
    this.failures = failures;
  }

  /** Get the Map from document ID to a successfully encrypted or decrypted document. */
  public ConcurrentMap<String, T> getDocuments() {
    return this.documents;
  }

  /**
   * Get a Map from the document ID to an exception that occured when encrypting or decrypting the
   * document
   */
  public ConcurrentMap<String, TenantSecurityException> getFailures() {
    return this.failures;
  }

  /** Returns whether the batch result had any successful encrypted/decrypted documents. */
  public boolean hasDocuments() {
    return this.documents.size() > 0;
  }

  /** Returns whether the batch result had any failures when encrypting/decrypting documents. */
  public boolean hasFailures() {
    return this.failures.size() > 0;
  }
}
