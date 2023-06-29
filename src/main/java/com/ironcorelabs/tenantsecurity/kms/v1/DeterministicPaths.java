package com.ironcorelabs.tenantsecurity.kms.v1;

abstract class DeterministicPaths {
  private String derivationPath;
  private String secretPath;

  public String getDerivationPath() {
    return derivationPath;
  }

  public String getSecretPath() {
    return secretPath;
  }
}
