package com.ironcorelabs.tenantsecurity.kms.v1;

import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;

import java.util.concurrent.ConcurrentMap;

/**
 * Holds result of a batch encrypt or decrypt operation which supports partial failure. Batch
 * operations can have both successes and failures and this class holds both fields.
 */
public final class BatchResult<T> {
  private final ConcurrentMap<String, T> successes;
  private final ConcurrentMap<String, TenantSecurityException> failures;

  public BatchResult(ConcurrentMap<String, T> successes,
      ConcurrentMap<String, TenantSecurityException> failures) {
    this.successes = successes;
    this.failures = failures;
  }

  /**
   * Get the Map from ID to successfully encrypted or decrypted data.
   *
   * @deprecated Use getSuccesses() instead
   */
  public ConcurrentMap<String, T> getDocuments() {
    return this.successes;
  }

  /**
   * Get the Map from ID to successfully encrypted or decrypted data.
   */
  public ConcurrentMap<String, T> getSuccesses() {
    return this.successes;
  }

  /**
   * Get a Map from the ID to an exception that occurred when encrypting or decrypting the data.
   */
  public ConcurrentMap<String, TenantSecurityException> getFailures() {
    return this.failures;
  }

  /**
   * Returns whether the batch result had any successful encrypted/decrypted data.
   *
   * @deprecated Use hasSuccesses() instead
   */
  public boolean hasDocuments() {
    return !this.successes.isEmpty();
  }

  /**
   * Returns whether the batch result had any successful encrypted/decrypted data.
   */
  public boolean hasSuccesses() {
    return !this.successes.isEmpty();
  }

  /**
   * Returns whether the batch result had any failures when encrypting/decrypting data.
   */
  public boolean hasFailures() {
    return !this.failures.isEmpty();
  }
}
