package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.HashMap;
import java.util.Map;

/**
 * Enum of error codes that can occur as part of requests to the Tenant Security Proxy Docker container.
 */
public enum TenantSecurityKMSErrorCodes {
    UNABLE_TO_MAKE_REQUEST(0, "Request to Tenant Security Proxy could not be made"),
    UNKNOWN_ERROR(100, "Unknown request error occured"),
    UNAUTHORIZED_REQUEST(101, "Request authorization header API key was incorrect."),
    INVALID_WRAP_BODY(102, "Request body was invalid for wrap request."),
    INVALID_UNWRAP_BODY(103, "Request body was invalid for unwrap request."),
    NO_PRIMARY_KMS_CONFIGURATION(200, "Tenant has no primary KMS configuration."),
    UNKNOWN_TENANT_OR_NO_ACTIVE_KMS_CONFIGURATIONS(201, "Tenant either doesn't exist or has no active KMS configurations."),
    KMS_CONFIGURATION_DISABLED(202, "Tenant configuration specified in EDEK is no longer active."),
    INVALID_PROVIDED_EDEK(203, "Provided EDEK was not valid."),
    KMS_WRAP_FAILED(204, "Request to KMS API to wrap key returned invalid results."),
    KMS_UNWRAP_FAILED(205, "Request to KMS API to unwrap key returned invalid results."),
    KMS_AUTHORIZATION_FAILED(206, "Request to KMS failed because the tenant credentials were invalid or have been revoked."),
    KMS_CONFIGURATION_INVALID(207, "Request to KMS failed because the key configuration was invalid or the necessary permissions for the operation were missing/revoked."),
    KMS_UNREACHABLE(208, "Request to KMS failed because KMS was unreachable.");

    private final int code;
    private final String message;
    private static Map<Integer, TenantSecurityKMSErrorCodes> intCodeToError = new HashMap<>();

    /**
     * Constructor for TenantSecurityKMSErrorCodes using the provided numerical code and readable error message.
     * @param code    Numerical error code for this error.
     * @param message Readable error message for this error.
     */
    TenantSecurityKMSErrorCodes(int code, String message){
        this.code = code;
        this.message = message;
    }

    static {
        //Create a map from the numerical code value to the ErrorCode instance so we can perform lookups when we
        //get a numerical value back from the Tenant Security Proxy API.
        for (TenantSecurityKMSErrorCodes errorCodes : TenantSecurityKMSErrorCodes.values()) {
            intCodeToError.put(errorCodes.code, errorCodes);
        }
    }

    /**
     * Get the numerical code value.
     * @return Numerical value for this error code.
     */
    public int getCode() {
        return this.code;
    }

    /**
     * Get the human readable error message associated with this error code.
     * @return Readable error message for this error code.
     */
    public String getMessage() {
        return this.message;
    }

    /**
     * Get an instance of an TenantSecurityKMSErrorCodes from the provided numerical code.
     * @param errorCode The numerical error code to lookup.
     * @return Instance of TenantSecurityKMSErrorCodes or null if provided code doesn't exist.
     */
    public static TenantSecurityKMSErrorCodes valueOf(int errorCode) {
        return (TenantSecurityKMSErrorCodes) intCodeToError.get(errorCode);
    }
}