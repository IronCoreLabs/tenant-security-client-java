package com.ironcorelabs.tenantsecurity.kms.v1;

import com.google.api.client.util.Key;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.*;

/**
 * Represents the JSON response object for errors that occur during wrap/unwrap of requests to the
 * Tenant Security Proxy.
 */
public class ErrorResponse {

  // just for testing
  protected ErrorResponse(int code, String message) {
    this.code = code;
    this.message = message;
  }

  // This empty constructor needed for JSON deserialization
  public ErrorResponse() {}

  @Key private int code;

  @Key private String message;

  public int getCode() {
    return code;
  }

  public String getMessage() {
    return message;
  }

  TenantSecurityException toTenantSecurityException(int httpStatusCode) {
    int errorCode = this.getCode();
    if (errorCode >= 0 && TenantSecurityErrorCodes.valueOf(errorCode) != null) {
      if (errorCode == 0) {
        return new TspServiceException(
            TenantSecurityErrorCodes.UNABLE_TO_MAKE_REQUEST, httpStatusCode, this.getMessage());
      } else if (errorCode >= 100 && errorCode <= 199) {
        return new TspServiceException(
            TenantSecurityErrorCodes.valueOf(errorCode), httpStatusCode, this.getMessage());
      } else if (errorCode >= 200 && errorCode <= 299) {
        return new KmsException(
            TenantSecurityErrorCodes.valueOf(errorCode), httpStatusCode, this.getMessage());
      } else if (errorCode >= 300 && errorCode <= 399) {
        return new SecurityEventException(
            TenantSecurityErrorCodes.valueOf(errorCode), httpStatusCode, this.getMessage());
      } else {
        return new TspServiceException(
            TenantSecurityErrorCodes.UNKNOWN_ERROR, errorCode, this.getMessage());
      }

    } else {
      return new TspServiceException(
          TenantSecurityErrorCodes.UNKNOWN_ERROR,
          httpStatusCode,
          "TSP status code outside of recognized range");
    }
  }
}
