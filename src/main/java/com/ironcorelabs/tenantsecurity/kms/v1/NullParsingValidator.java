package com.ironcorelabs.tenantsecurity.kms.v1;

abstract class NullParsingValidator {
  /**
   * Throws an IllegalArgumentException if any of the fields were parsed as null.
   */
  abstract void ensureNoNullsOrThrow() throws IllegalArgumentException;
}
