package com.ironcorelabs.tenantsecurity.kms.v1;

import com.google.api.client.util.Key;

/**
 * An EDEK made by wrapping an existing encrypted document with a tenant's KMS, in Base64 format.
 */
public class RekeyedDocumentKey implements NullParsingValidator {
  @Key
  private String edek;

  public String getEdek() {
    return this.edek;
  }

  @Override
  public void ensureNoNullsOrThrow() throws IllegalArgumentException {
    if (edek == null)
      throw new IllegalArgumentException(
          "Rekeyed document key response from the Tenant Security Proxy was not valid base64.");
  }
}
