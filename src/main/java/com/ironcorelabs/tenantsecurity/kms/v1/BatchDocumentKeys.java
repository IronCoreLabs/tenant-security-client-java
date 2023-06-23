package com.ironcorelabs.tenantsecurity.kms.v1;

import com.google.api.client.util.Key;
import java.util.Map;

/**
 * A map from a document ID to a either the wrapped or unwrapped version of a documents keys. Also
 * includes a map of failures if any problems occurred when performing the batch wrap operation.
 */
public class BatchDocumentKeys<T> {
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
}
