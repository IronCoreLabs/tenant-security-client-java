package com.ironcorelabs.tenantsecurity.kms.v1.exception;

import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityErrorCodes;

/**
 * Errors originating from internal TSC operations.
 */
public class TscException extends TenantSecurityException {

  // ID for serialization. Should be incremented whenever we make
  // serialization-breaking changes to this class
  // which is described in
  // https://docs.oracle.com/javase/6/docs/platform/serialization/spec/version.html#6678.
  private static final long serialVersionUID = 2L;

  /**
   * Create a new TscException with the provided error code and cause.
   *
   * @param errorCode Error code corresponding with this error.
   * @param errorMessage The readable error message.
   * @param cause The Throwable that caused this one.
   */
  public TscException(TenantSecurityErrorCodes errorCode, String errorMessage, Throwable cause) {
    super(errorCode, 0, errorMessage, cause);
  }

  /**
   * Create a new TscException with the provided error code.
   *
   * @param errorCode Error code corresponding with this error.
   * @param errorMessage The readable error message.
   */
  public TscException(TenantSecurityErrorCodes errorCode, String errorMessage) {
    this(errorCode, errorMessage, null);
  }


  /**
   * Create a new TscException with the provided cause.
   *
   * @param errorCode Error code corresponding with this error.
   * @param cause The Throwable that caused this one.
   */
  public TscException(TenantSecurityErrorCodes errorCode, Throwable cause) {
    this(errorCode, errorCode.getMessage(), cause);
  }
}
