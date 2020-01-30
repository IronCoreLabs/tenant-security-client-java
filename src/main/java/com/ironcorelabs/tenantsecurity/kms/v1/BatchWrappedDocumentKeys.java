package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Map;

import com.google.api.client.util.Key;

/**
 * A map from a document ID to a DEK and its encrypted form (EDEK) wrapped with the tenants KMS, both in base64 format. Also
 * includes a map of failures if any problems occured when performing the batch wrap operation.
 */
public class BatchWrappedDocumentKeys {
    @Key
    private Map<String, WrappedDocumentKey> keys;

    @Key
    private Map<String, ErrorResponse> failures;

    public Map<String, WrappedDocumentKey> getKeys(){
        return this.keys;
    }

    public WrappedDocumentKey getKey(String index){
        return this.keys.get(index);
    }

    public Map<String, ErrorResponse> getFailures(){
        return this.failures;
    }

    public boolean hasSuccesses(){
        return this.keys.size() > 0;
    }

    public boolean hasFailures(){
        return this.failures.size() > 0;
    }
}