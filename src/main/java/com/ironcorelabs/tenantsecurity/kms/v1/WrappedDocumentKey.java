package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Base64;

import com.google.api.client.util.Key;

/**
 * A new DEK wrapped by the tenant's KMS and its encrypted form (EDEK), both in Base64 format.
 */
public class WrappedDocumentKey extends NullParsingValidator {
  @Key
  private String dek;

  @Key
  private String edek;

  public byte[] getDekBytes() {
    try {
      return Base64.getDecoder().decode(this.dek);
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "Wrapped document key response from the Tenant Security Proxy was not valid base64.");
    }
  }

  public String getEdek() {
    return this.edek;
  }

  @Override
  void ensureNoNullsOrThrow() throws IllegalArgumentException {
    if (edek == null || dek == null)
      throw new IllegalArgumentException(
          "Wrapped document key response from the Tenant Security Proxy was not valid base64.");
  }
}
