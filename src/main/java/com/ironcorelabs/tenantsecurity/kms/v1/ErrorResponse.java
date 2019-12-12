package com.ironcorelabs.tenantsecurity.kms.v1;

import com.google.api.client.util.Key;

/**
 * Represents the JSON response object for errors that occur during wrap/unwrap
 * of requests to the Tenant Security Proxy.
 */
public class ErrorResponse {
    @Key
    private int code;

    @Key
    private String message;

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}