package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.CompletableFuture;

/**
 * Interface for document decryption capabilities. Implemented by both TenantSecurityClient (for
 * standard decrypt operations that unwrap the EDEK each time) and CachedKeyDecryptor (for repeated
 * decrypts using a cached DEK).
 */
public interface DocumentDecryptor {

  /**
   * Decrypt the provided EncryptedDocument and return the decrypted fields.
   *
   * @param encryptedDocument Document to decrypt which includes encrypted bytes as well as EDEK.
   * @param metadata Metadata about the document being decrypted.
   * @return CompletableFuture resolving to PlaintextDocument with decrypted field bytes.
   */
  CompletableFuture<PlaintextDocument> decrypt(EncryptedDocument encryptedDocument,
      DocumentMetadata metadata);

  /**
   * Decrypt a stream using the provided EDEK.
   *
   * @param edek Encrypted document encryption key.
   * @param input A stream representing the encrypted document.
   * @param output An output stream to write the decrypted document to. Note that this output should
   *        not be used until after the future exits successfully because the GCM tag is not fully
   *        verified until that time.
   * @param metadata Metadata about the document being decrypted.
   * @return Future which will complete when input has been decrypted.
   */
  CompletableFuture<Void> decryptStream(String edek, InputStream input, OutputStream output,
      DocumentMetadata metadata);
}
