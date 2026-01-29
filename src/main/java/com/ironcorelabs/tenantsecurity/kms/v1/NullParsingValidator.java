package com.ironcorelabs.tenantsecurity.kms.v1;

interface NullParsingValidator {
  void ensureNoNullsOrThrow() throws IllegalArgumentException;
}
