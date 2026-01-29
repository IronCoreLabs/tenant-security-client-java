package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Base64;

import com.google.api.client.util.Key;

/**
 * Represents the JSON response object from the document/unwrap endpoint which includes the dek.
 */
public class UnwrappedDocumentKey extends NullParsingValidator {
  @Key
  private String dek;

  public byte[] getDekBytes() {
    try {
      return Base64.getDecoder().decode(this.dek);
    } catch (Exception e) {
      throw new IllegalArgumentException(
          "Unwrap DEK response from the Tenant Security Proxy was not valid base64.");
    }
  }

  @Override
  void ensureNoNullsOrThrow() throws IllegalArgumentException {
    if (dek == null)
      throw new IllegalArgumentException(
          "Unwrap DEK response from the Tenant Security Proxy was not valid base64.");
  }
}
