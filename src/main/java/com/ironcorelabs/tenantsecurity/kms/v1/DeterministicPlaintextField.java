package com.ironcorelabs.tenantsecurity.kms.v1;

public final class DeterministicPlaintextField extends DeterministicPaths {
  private final byte[] plaintextField;
  private final String derivationPath;
  private final String secretPath;

  public DeterministicPlaintextField(byte[] plaintextField, String derivationPath,
      String secretPath) {
    this.plaintextField = plaintextField;
    this.derivationPath = derivationPath;
    this.secretPath = secretPath;
  }

  public byte[] getPlaintextField() {
    return plaintextField;
  }

  public String getDerivationPath() {
    return derivationPath;
  }

  public String getSecretPath() {
    return secretPath;
  }
}
