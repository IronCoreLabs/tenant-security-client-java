package com.ironcorelabs.tenantsecurity.kms.v1;

public class StreamingResponse {
    private final String edek;

    public StreamingResponse(String edek) {
        this.edek = edek;
    }

    /**
     * Shorthand method for getEncryptedDocumentEncryptionKey()
     */
    public String getEdek() {
        return getEncryptedDocumentEncryptionKey();
    }

    /**
     * Get the document's encrypted document encryption key (EDEK).
     */
    public String getEncryptedDocumentEncryptionKey() {
        return edek;
    }
}
