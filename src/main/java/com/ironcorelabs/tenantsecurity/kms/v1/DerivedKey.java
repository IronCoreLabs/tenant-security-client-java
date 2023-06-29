package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Base64;
import com.google.api.client.util.Key;

public class DerivedKey {
  @Key
  private String derivedKey;
  @Key
  private long tenantSecretId;
  @Key
  private boolean current;

  // This empty constructor needed for JSON deserialization
  public DerivedKey() {}

  // Needed for testing
  protected DerivedKey(String derivedKey, long tenantSecretId, boolean current) {
    this.derivedKey = derivedKey;
    this.tenantSecretId = tenantSecretId;
    this.current = current;
  }

  public byte[] getDerivedKeyBytes() {
    try {
      return Base64.getDecoder().decode(this.derivedKey);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "Derive keys response from the Tenant Security Proxy was not valid base64.");
    }
  }

  public long getTenantSecretId() {
    return tenantSecretId;
  }

  public boolean isCurrent() {
    return current;
  }
}
