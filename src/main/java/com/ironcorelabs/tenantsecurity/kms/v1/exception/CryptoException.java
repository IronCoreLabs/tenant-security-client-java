package com.ironcorelabs.tenantsecurity.kms.v1.exception;

/**
 * This is meant to convey that something has happened in the crypto apis such as signature
 * validation failure, incorrect IV length, etc.
 */
public class CryptoException extends Exception {
  // ID for serialization. Should be incremented whenever we make
  // serialization-breaking changes to this class
  // which is described in
  // https://docs.oracle.com/javase/6/docs/platform/serialization/spec/version.html#6678.
  private static final long serialVersionUID = 1L;

  public CryptoException(String message) {
    super(message);
  }

}
