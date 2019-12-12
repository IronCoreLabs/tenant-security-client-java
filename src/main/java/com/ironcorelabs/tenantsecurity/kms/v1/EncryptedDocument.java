package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Map;

/**
 * Holds result of encrypting a document with the Tenant Security KMS client. Contains the document's
 * fields in encrypted form and the encrypted key (EDEK) that was used to
 * encrypt those fields.
 */
public final class EncryptedDocument {
    private final Map<String, byte[]> encryptedFields;
    private final String edek;

    public EncryptedDocument(Map<String, byte[]> encryptedFields, String edek) {
        this.encryptedFields = encryptedFields;
        this.edek = edek;
    }

    /**
     * Get the document's encrypted document encryption key (EDEK).
     */
    public String getEncryptedDocumentEncryptionKey() {
        return edek;
    }

    /**
     * Shorthand method for getEncryptedDocumentEncryptionKey()
     */
    public String getEdek() {
        return getEncryptedDocumentEncryptionKey();
    }

    /**
     * Get the encrypted map of document fields by id/name (String) to encrypted
     * bytes (byte[]).
     *
     * @return Encrypted document map.
     */
    public Map<String, byte[]> getEncryptedFields() {
        return encryptedFields;
    }
}