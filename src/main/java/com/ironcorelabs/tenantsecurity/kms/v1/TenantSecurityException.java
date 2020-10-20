package com.ironcorelabs.tenantsecurity.kms.v1;

/**
 * Represents an Exception that occurred within the Tenant Security Proxy Docker
 * container. Exposes error codes to better communicate the type of error that
 * occurred when trying to wrap or unwrap a key from the tenants KMS.
 */
public class TenantSecurityException extends Exception {
    // ID for serialization. Should be incremented whenever we make
    // serialization-breaking changes to this class
    // which is described in
    // https://docs.oracle.com/javase/6/docs/platform/serialization/spec/version.html#6678.
    private static final long serialVersionUID = 2L;
    private TenantSecurityErrorCodes errorCode;
    private int httpResponseCode;

    /**
     * Create a new TenantSecurityException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        TSP generated code corresponding with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     * @param errorMessage     The readable error message returned from the Tenant
     *                         Security Proxy for this error.
     * @param cause            The Throwable that caused this one.
     */
    public TenantSecurityException(TenantSecurityErrorCodes errorCode, int httpResponseCode, String errorMessage, Throwable cause) {
        super(errorMessage, cause);
        this.errorCode = errorCode;
        this.httpResponseCode = httpResponseCode;
    }

    /**
     * Create a new TenantSecurityException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        TSP generated code corresponding with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     * @param errorMessage     The readable error message returned from the Tenant
     *                         Security Proxy for this error.
     */
    public TenantSecurityException(TenantSecurityErrorCodes errorCode, int httpResponseCode, String errorMessage) {
        this(errorCode, httpResponseCode, errorMessage, null);
    }

    /**
     * Create a new TenantSecurityException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        TSP generated code corresponding with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     * @param cause            The Throwable that caused this one.
     */
    public TenantSecurityException(TenantSecurityErrorCodes errorCode, int httpResponseCode, Throwable cause) {
        this(errorCode, httpResponseCode, errorCode.getMessage(), cause);
    }

    /**
     * Create a new TenantSecurityException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        TSP generated code corresponding with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     */
    public TenantSecurityException(TenantSecurityErrorCodes errorCode, int httpResponseCode) {
        this(errorCode, httpResponseCode, errorCode.getMessage(), null);
    }

    /**
     * Create a new TenantSecurityException when the request to the API couldn't
     * be made.
     *
     * @param errorCode TSP generated code corresponding with this error.
     * @param cause     The Throwable that caused this one.
     */
    public TenantSecurityException(TenantSecurityErrorCodes errorCode, Throwable cause) {
        this(errorCode, 0, errorCode.getMessage(), cause);
    }

    /**
     * Create a new TenantSecurityException when the request to the API couldn't
     * be made.
     *
     * @param errorCode TSP generated code corresponding with this error.
     */
    public TenantSecurityException(TenantSecurityErrorCodes errorCode) {
        this(errorCode, 0);
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