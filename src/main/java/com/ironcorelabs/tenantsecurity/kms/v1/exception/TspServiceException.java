package com.ironcorelabs.tenantsecurity.kms.v1.exception;

import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityErrorCodes;

public class TspServiceException extends TenantSecurityException {

    // ID for serialization. Should be incremented whenever we make
    // serialization-breaking changes to this class
    // which is described in
    // https://docs.oracle.com/javase/6/docs/platform/serialization/spec/version.html#6678.
    private static final long serialVersionUID = 2L;
    private TenantSecurityErrorCodes errorCode;
    private int httpResponseCode;

    /**
     * Create a new TspServiceException with the provided error code and HTTP
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
    public TspServiceException(TenantSecurityErrorCodes errorCode, int httpResponseCode, String errorMessage,
            Throwable cause) {
        super(errorCode, httpResponseCode, errorMessage, cause);
    }

    /**
     * Create a new TspServiceException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        TSP generated code corresponding with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     * @param errorMessage     The readable error message returned from the Tenant
     *                         Security Proxy for this error.
     */
    public TspServiceException(TenantSecurityErrorCodes errorCode, int httpResponseCode, String errorMessage) {
        this(errorCode, httpResponseCode, errorMessage, null);
    }

    /**
     * Create a new TspServiceException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        TSP generated code corresponding with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     * @param cause            The Throwable that caused this one.
     */
    public TspServiceException(TenantSecurityErrorCodes errorCode, int httpResponseCode, Throwable cause) {
        this(errorCode, httpResponseCode, errorCode.getMessage(), cause);
    }

    /**
     * Create a new TspServiceException with the provided error code and HTTP
     * status code.
     *
     * @param errorCode        TSP generated code corresponding with this
     *                         error.
     * @param httpResponseCode The HTTP response code returned from the
     *                         Tenant Security Proxy for this error.
     */
    public TspServiceException(TenantSecurityErrorCodes errorCode, int httpResponseCode) {
        this(errorCode, httpResponseCode, errorCode.getMessage(), null);
    }

    /**
     * Create a new TspServiceException when the request to the API couldn't
     * be made.
     *
     * @param errorCode TSP generated code corresponding with this error.
     * @param cause     The Throwable that caused this one.
     */
    public TspServiceException(TenantSecurityErrorCodes errorCode, Throwable cause) {
        this(errorCode, 0, errorCode.getMessage(), cause);
    }

    /**
     * Create a new TspServiceException when the request to the API couldn't
     * be made.
     *
     * @param errorCode TSP generated code corresponding with this error.
     */
    public TspServiceException(TenantSecurityErrorCodes errorCode) {
        this(errorCode, 0);
    }
}
