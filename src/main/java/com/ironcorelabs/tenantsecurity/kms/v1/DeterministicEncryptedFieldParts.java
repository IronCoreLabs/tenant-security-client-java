package com.ironcorelabs.tenantsecurity.kms.v1;

class DeterministicEncryptedFieldParts {
  private long tenantSecretId;


  private byte[] encryptedBytes;


  public DeterministicEncryptedFieldParts(long tenantSecretId, byte[] encryptedBytes) {
    this.tenantSecretId = tenantSecretId;
    this.encryptedBytes = encryptedBytes;
  }

  public long getTenantSecretId() {
    return tenantSecretId;
  }

  public byte[] getEncryptedBytes() {
    return encryptedBytes;
  }
}
