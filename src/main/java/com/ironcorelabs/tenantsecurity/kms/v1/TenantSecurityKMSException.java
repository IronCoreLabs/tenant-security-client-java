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

    /**
     * Create a new TenantSecurityKMSException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        The EncryptionServiceErrorCode that occured with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     * @param errorMessage     The readable error message returned from the Tenant
     *                         Security Proxy for this error.
     * @param cause            The Throwable that caused this one.
     */
    public TenantSecurityKMSException(TenantSecurityKMSErrorCodes errorCode, int httpResponseCode, String errorMessage, Throwable cause) {
        super(errorMessage, cause);
        this.errorCode = errorCode;
        this.httpResponseCode = httpResponseCode;
    }

    /**
     * Create a new TenantSecurityKMSException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        The EncryptionServiceErrorCode that occured with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     * @param errorMessage     The readable error message returned from the Tenant
     *                         Security Proxy for this error.
     */
    public TenantSecurityKMSException(TenantSecurityKMSErrorCodes errorCode, int httpResponseCode, String errorMessage) {
        this(errorCode, httpResponseCode, errorMessage, null);
    }

    /**
     * Create a new TenantSecurityKMSException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        The EncryptionServiceErrorCode that occured with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     * @param cause            The Throwable that caused this one.
     */
    public TenantSecurityKMSException(TenantSecurityKMSErrorCodes errorCode, int httpResponseCode, Throwable cause) {
        this(errorCode, httpResponseCode, errorCode.getMessage(), cause);
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
        this(errorCode, httpResponseCode, errorCode.getMessage(), null);
    }

    /**
     * Create a new TenantSecurityKMSException when the request to the API couldn't
     * be made.
     *
     * @param errorCode The EncryptionServiceErrorCode that occured with this error.
     * @param cause     The Throwable that caused this one.
     */
    public TenantSecurityKMSException(TenantSecurityKMSErrorCodes errorCode, Throwable cause) {
        this(errorCode, 0, errorCode.getMessage(), cause);
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
     * Get an error message. Can contain additional
     * information about the specifics of why a request failed including errors specific to the KMS
     * type that failed.
     *
     * @return The readable error message.
     * @deprecated Use {@link #getMessage()} instead.
     */
    @Deprecated
    public String getErrorMessage(){
        return this.getMessage();
    }
}