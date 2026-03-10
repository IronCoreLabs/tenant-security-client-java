package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Interface for document encryption capabilities. Implemented by both TenantSecurityClient (for
 * standard encrypt operations that wrap a new DEK each time) and CachedKeyEncryptor (for repeated
 * encrypts using a cached DEK).
 */
public interface DocumentEncryptor {

  /**
   * Encrypt the provided document fields and return the resulting encrypted document.
   *
   * @param document Map of field names to plaintext bytes to encrypt.
   * @param metadata Metadata about the document being encrypted.
   * @return CompletableFuture resolving to EncryptedDocument with encrypted field bytes and EDEK.
   */
  CompletableFuture<EncryptedDocument> encrypt(Map<String, byte[]> document,
      DocumentMetadata metadata);

  /**
   * Encrypt a stream of bytes.
   *
   * @param input The input stream of plaintext bytes to encrypt.
   * @param output The output stream to write encrypted bytes to.
   * @param metadata Metadata about the document being encrypted.
   * @return CompletableFuture resolving to StreamingResponse containing the EDEK.
   */
  CompletableFuture<StreamingResponse> encryptStream(InputStream input, OutputStream output,
      DocumentMetadata metadata);

  /**
   * Encrypt a batch of documents. Supports partial failure via {@link BatchResult}.
   *
   * @param plaintextDocuments Map of document ID to map of fields to encrypt.
   * @param metadata Metadata about all of the documents being encrypted.
   * @return Collection of successes and failures that occurred during operation.
   */
  CompletableFuture<BatchResult<EncryptedDocument>> encryptBatch(
      Map<String, Map<String, byte[]>> plaintextDocuments, DocumentMetadata metadata);
}
