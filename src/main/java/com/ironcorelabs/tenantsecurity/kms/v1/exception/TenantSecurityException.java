package com.ironcorelabs.tenantsecurity.kms.v1.exception;

import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityErrorCodes;

/**
 * Represents an Exception that occurred within or while attempting to call the Tenant Security
 * Proxy Docker container. Exposes error codes to better communicate the type of error that occurred
 * when trying to wrap or unwrap a key from the tenants KMS.
 *
 * <p>This is intended to be a superclass, but not to be constructed directely
 */
public class TenantSecurityException extends Exception {
  // ID for serialization. Should be incremented whenever we make
  // serialization-breaking changes to this class
  // which is described in
  // https://docs.oracle.com/javase/6/docs/platform/serialization/spec/version.html#6678.
  private static final long serialVersionUID = 2L;
  protected TenantSecurityErrorCodes errorCode;
  protected int httpResponseCode;

  /**
   * Package private constructor so that subclasses have a common way of setting the provided error
   * code and HTTP status code.
   *
   * @param errorCode TSP generated code corresponding with this error.
   * @param httpResponseCode The HTTP response code returned from the Tenant Security Proxy for this
   *     error.
   * @param errorMessage The readable error message returned from the Tenant Security Proxy for this
   *     error.
   * @param cause The Throwable that caused this one.
   */
  protected TenantSecurityException(
      TenantSecurityErrorCodes errorCode,
      int httpResponseCode,
      String errorMessage,
      Throwable cause) {
    super(errorMessage, cause);
    this.errorCode = errorCode;
    this.httpResponseCode = httpResponseCode;
  }

  /**
   * Get the TenantSecurityErrorCodes instance this error represents.
   *
   * @return The numerical error code for this error.
   */
  public TenantSecurityErrorCodes getErrorCode() {
    return errorCode;
  }

  /**
   * Get the HTTP response code that was returned from the Tenant Security Proxy. May be 0 if the
   * request couldn't be made.
   *
   * @return The numerical HTTP response code returned from the Tenant Security Proxy.
   */
  public int getHttpResponseCode() {
    return httpResponseCode;
  }
}
