package com.ironcorelabs.tenantsecurity.kms.v1;

class DeterministicEncryptedFieldParts {
  private long tenantSecretId;
  private byte[] encryptedBytes;

  DeterministicEncryptedFieldParts(long tenantSecretId, byte[] encryptedBytes) {
    this.tenantSecretId = tenantSecretId;
    this.encryptedBytes = encryptedBytes;
  }

  long getTenantSecretId() {
    return tenantSecretId;
  }

  byte[] getEncryptedBytes() {
    return encryptedBytes;
  }
}
