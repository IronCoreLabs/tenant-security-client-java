package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Map;
import com.google.api.client.util.Key;

/**
 * A map from a document ID to a either the wrapped or unwrapped version of a documents keys. Also
 * includes a map of failures if any problems occurred when performing the batch wrap operation.
 */
public class BatchDocumentKeys<T> implements NullParsingValidator {
  @Key
  private Map<String, T> keys;

  @Key
  private Map<String, ErrorResponse> failures;

  public Map<String, T> getKeys() {
    return this.keys;
  }

  public Map<String, ErrorResponse> getFailures() {
    return this.failures;
  }

  @Override
  public void ensureNoNullsOrThrow() throws IllegalArgumentException {
    if (keys == null || failures == null)
      throw new IllegalArgumentException(
          "Batch response from the Tenant Security Proxy was not valid.");
  }
}
