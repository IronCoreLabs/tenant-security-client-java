package com.ironcorelabs.tenantsecurity.kms.v1;

public final class DeterministicEncryptedField extends DeterministicPaths {
  private final byte[] encryptedField;
  private final String derivationPath;
  private final String secretPath;

  public DeterministicEncryptedField(byte[] encryptedField, String derivationPath,
      String secretPath) {
    this.encryptedField = encryptedField;
    this.derivationPath = derivationPath;
    this.secretPath = secretPath;
  }

  public byte[] getEncryptedField() {
    return encryptedField;
  }

  public String getDerivationPath() {
    return derivationPath;
  }

  public String getSecretPath() {
    return secretPath;
  }
}
