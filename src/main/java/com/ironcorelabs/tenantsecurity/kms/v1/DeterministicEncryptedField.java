package com.ironcorelabs.tenantsecurity.kms.v1;

/**
 * Holds the result of deterministically encrypting a field with the Deterministic Tenant Security
 * KMS client. Contains the encrypted fields and the paths that were used to encrypt those fields.
 */
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

  /**
   * Get the encrypted field data.
   */
  public byte[] getEncryptedField() {
    return encryptedField;
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
