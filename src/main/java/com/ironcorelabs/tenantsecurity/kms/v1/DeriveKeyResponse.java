package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import com.google.api.client.util.Key;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TspServiceException;

public class DeriveKeyResponse {
  @Key
  private boolean hasPrimaryConfig;
  @Key
  private Map<String, Map<String, DerivedKey[]>> derivedKeys;

  public boolean getHasPrimaryConfig() {
    return hasPrimaryConfig;
  }

  // public DeriveKeyResponse(boolean hasPrimaryConfig,
  // Map<String, Map<String, DerivedKey[]>> derivedKeys) {
  // this.hasPrimaryConfig = hasPrimaryConfig;
  // this.derivedKeys = derivedKeys;
  // }

  CompletableFuture<DerivedKey[]> getDerivedKeys(String secretPath, String derivationPath) {
    Map<String, DerivedKey[]> derivedDerivationPaths = derivedKeys.get(secretPath);
    if (derivedDerivationPaths == null) {
      return CompletableFuture.failedFuture(new TspServiceException(
          TenantSecurityErrorCodes.UNKNOWN_ERROR, 100, "TSP failed to derive keys"));
    }
    DerivedKey[] derivedKeys = derivedDerivationPaths.get(derivationPath);
    if (derivedKeys == null) {
      return CompletableFuture.failedFuture(new TspServiceException(
          TenantSecurityErrorCodes.UNKNOWN_ERROR, 100, "TSP failed to derive keys"));
    }
    return CompletableFuture.completedFuture(derivedKeys);
  }
}
