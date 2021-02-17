package com.ironcorelabs.tenantsecurity.kms.v1;

import com.google.api.client.util.Key;

/**
 * An EDEK made by wrapping an existing encrypted document with a tenant's KMS, in
 * Base64 format.
 */
public class RekeyedDocumentKey {
    @Key
    private String edek;

    public String getEdek() {
        return this.edek;
    }
}