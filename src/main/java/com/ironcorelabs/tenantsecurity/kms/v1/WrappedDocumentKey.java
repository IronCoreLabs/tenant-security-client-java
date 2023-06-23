package com.ironcorelabs.tenantsecurity.kms.v1;

import com.google.api.client.util.Key;
import java.util.Base64;

/** A new DEK wrapped by the tenant's KMS and its encrypted form (EDEK), both in Base64 format. */
public class WrappedDocumentKey {
  @Key private String dek;

  @Key private String edek;

  public byte[] getDekBytes() {
    try {
      return Base64.getDecoder().decode(this.dek);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "Wrapped document key response from the Tenant Security Proxy was not valid base64.");
    }
  }

  public String getEdek() {
    return this.edek;
  }
}
