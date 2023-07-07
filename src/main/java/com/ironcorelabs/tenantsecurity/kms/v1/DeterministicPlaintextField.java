package com.ironcorelabs.tenantsecurity.kms.v1;

/**
 * Represents a plaintext (non-encrypted) field. Also contains the derivation and secret paths that
 * will be used to deterministically encrypt the field.
 */
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

  /**
   * Get the plaintext field data.
   */
  public byte[] getPlaintextField() {
    return plaintextField;
  }

  /**
   * Get the derivation path used for deterministic encryption operations.
   */
  public String getDerivationPath() {
    return derivationPath;
  }

  /**
   * Get the secret path used for deterministic encryption operations.
   */
  public String getSecretPath() {
    return secretPath;
  }
}
