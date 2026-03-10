package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.Closeable;

/**
 * Common lifecycle methods shared by {@link CachedEncryptor} and {@link CachedDecryptor}. Provides
 * access to the cached EDEK, status checks, operation counting, and resource cleanup.
 */
public interface CachedKeyLifecycle extends Closeable {

  /**
   * Get the EDEK associated with this cached key.
   *
   * @return The EDEK string
   */
  String getEdek();

  /**
   * Check if this cached key has been closed.
   *
   * @return true if close() has been called
   */
  boolean isClosed();

  /**
   * Check if this cached key has expired due to timeout.
   *
   * @return true if the timeout has elapsed since creation
   */
  boolean isExpired();

  /**
   * Get the total number of successful operations performed with this cached key.
   *
   * @return The total operation count
   */
  int getOperationCount();

  /**
   * Securely zero the DEK and release resources. After calling close(), all operations will fail.
   * This override narrows the Closeable contract to not throw IOException.
   */
  @Override
  void close();
}
