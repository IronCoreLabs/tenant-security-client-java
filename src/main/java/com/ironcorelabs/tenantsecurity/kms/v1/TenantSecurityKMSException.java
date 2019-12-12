package com.ironcorelabs.tenantsecurity.kms.v1;

/**
 * Represents an Exception that occured within the Tenant Security Proxy Docker
 * container. Exposes error codes to better communicate the type of error that
 * occured when trying to wrap or unwrap a key from the tenants KMS.
 */
public class TenantSecurityKMSException extends Exception {
    // ID for serialization. Should be incremented whenever we make
    // seralization-breaking changes to this class
    // which is described in
    // https://docs.oracle.com/javase/6/docs/platform/serialization/spec/version.html#6678.
    private static final long serialVersionUID = 1L;
    private TenantSecurityKMSErrorCodes errorCode;
    private int httpResponseCode;
    private String errorMessage;

    /**
     * Create a new TenantSecurityKMSException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        The EncryptionServiceErrorCode that occured with this
     *                         error.
     * @param errorMessage     The readable error message returned from the Tenant
     *                         Security Proxy for this error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     */
    public TenantSecurityKMSException(TenantSecurityKMSErrorCodes errorCode, String errorMessage, int httpResponseCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
        this.httpResponseCode = httpResponseCode;
        this.errorMessage = errorMessage;
    }

    /**
     * Create a new TenantSecurityKMSException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        The EncryptionServiceErrorCode that occured with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     */
    public TenantSecurityKMSException(TenantSecurityKMSErrorCodes errorCode, int httpResponseCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
        this.httpResponseCode = httpResponseCode;
    }

    /**
     * Create a new TenantSecurityKMSException when the request to the API couldn't
     * be made.
     *
     * @param errorCode The EncryptionServiceErrorCode that occured with this error.
     */
    public TenantSecurityKMSException(TenantSecurityKMSErrorCodes errorCode) {
        this(errorCode, 0);
    }

    /**
     * Get the TenantSecurityKMSErrorCodes instance this error represents.
     *
     * @return The numerical error code for this error.
     */
    public TenantSecurityKMSErrorCodes getErrorCode() {
        return errorCode;
    }

    /**
     * Get the HTTP response code that was returned from the Tenant Security Proxy. May
     * be 0 if the request couldn't be made.
     *
     * @return The numerical HTTP response code returned from the Tenant Security Proxy.
     */
    public int getHttpResponseCode() {
        return httpResponseCode;
    }

    /**
     * Get the HTTP error message sent back from the Tenant Security Proxy. Can contain additional
     * information about the specifics of why a request failed including errors specific to the KMS
     * type that failed. May be be an empty string if no error was sent.
     *
     * @return The readable error message returned from the Tenant Security Proxy.
     */
    public String getErrorMessage(){
        return errorMessage;
    }
}