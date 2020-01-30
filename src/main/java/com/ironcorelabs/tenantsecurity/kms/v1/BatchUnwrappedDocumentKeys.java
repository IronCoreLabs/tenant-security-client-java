package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Map;

import com.google.api.client.util.Key;

/**
 * A map from an EDEK ID to a DEK decrypted with the tenants KMS, both in base64
 * format. Also includes a map of failures if any problems occured when
 * performing the batch unwrap operation.
 */
public class BatchUnwrappedDocumentKeys {
    @Key
    private Map<String, UnwrappedDocumentKey> keys;

    @Key
    private Map<String, ErrorResponse> failures;

    public Map<String, UnwrappedDocumentKey> getKeys() {
        return this.keys;
    }

    public Map<String, ErrorResponse> getFailures() {
        return this.failures;
    }
}