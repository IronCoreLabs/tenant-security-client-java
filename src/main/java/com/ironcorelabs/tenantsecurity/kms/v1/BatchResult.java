package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Map;

/**
 * Holds result of a batch encrypt or decrypt operation which supports partial failure. Batch operations
 * can have both successes and failures and this class holds both fields.
 */
public final class BatchResult<T> {
    private final Map<String, T> documents;
    private final Map<String, TenantSecurityKMSException> batchFailures;

    public BatchResult(Map<String, T> documents, Map<String, TenantSecurityKMSException> failures) {
        this.documents = documents;
        this.batchFailures = failures;
    }

    /**
     * Get the Map from document ID to a successfully encrypted or decrypted document.
     */
    public Map<String, T> getDocuments(){
        return this.documents;
    }

    /**
     * Get a Map from the document ID to an exception that occured when encrypting or decrypting the document
     */
    public Map<String, TenantSecurityKMSException> getFailures(){
        return this.batchFailures;
    }

    /**
     * Returns whether the batch result had any successful encrypted/decrypted documents.
     */
    public boolean hasDocuments(){
        return this.documents.size() > 0;
    }

    /**
     * Returns whether the batch result had any failures when encrypting/decrypting documents.
     */
    public boolean hasFailures(){
        return this.batchFailures.size() > 0;
    }
}