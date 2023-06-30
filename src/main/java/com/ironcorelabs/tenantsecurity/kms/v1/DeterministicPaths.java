package com.ironcorelabs.tenantsecurity.kms.v1;

abstract class DeterministicPaths {
  private String derivationPath;
  private String secretPath;

  String getDerivationPath() {
    return derivationPath;
  }

  String getSecretPath() {
    return secretPath;
  }
}
