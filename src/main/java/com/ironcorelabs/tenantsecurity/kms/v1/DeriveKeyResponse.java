package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import com.google.api.client.util.Key;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TspServiceException;

public final class DeriveKeyResponse extends NullParsingValidator {
  @Key
  private boolean hasPrimaryConfig;
  @Key
  private Map<String, Map<String, DerivedKey[]>> derivedKeys;

  // This empty constructor needed for JSON deserialization
  public DeriveKeyResponse() {}

  // Needed for testing
  DeriveKeyResponse(boolean hasPrimaryConfig, Map<String, Map<String, DerivedKey[]>> derivedKeys) {
    this.hasPrimaryConfig = hasPrimaryConfig;
    this.derivedKeys = derivedKeys;
  }

  boolean getHasPrimaryConfig() {
    return hasPrimaryConfig;
  }

  CompletableFuture<DerivedKey[]> getDerivedKeys(String secretPath, String derivationPath) {
    Map<String, DerivedKey[]> derivedDerivationPaths = derivedKeys.get(secretPath);
    if (derivedDerivationPaths == null) {
      return CompletableFuture.failedFuture(new TspServiceException(
          TenantSecurityErrorCodes.UNKNOWN_ERROR, 100, "TSP failed to derive keys."));
    }
    DerivedKey[] derivedKeys = derivedDerivationPaths.get(derivationPath);
    if (derivedKeys == null) {
      return CompletableFuture.failedFuture(new TspServiceException(
          TenantSecurityErrorCodes.UNKNOWN_ERROR, 100, "TSP failed to derive keys."));
    }
    return CompletableFuture.completedFuture(derivedKeys);
  }

  @Override
  void ensureNoNullsOrThrow() throws IllegalArgumentException {
    if (derivedKeys == null)
      throw new IllegalArgumentException("TSP failed to derive keys.");
  }
}
