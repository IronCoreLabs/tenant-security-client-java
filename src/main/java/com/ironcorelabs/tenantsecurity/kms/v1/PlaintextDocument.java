package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Map;

/**
 * Represents a plaintext (non-encrypted) document which can have 1-N fields. Also contains the
 * encrypted document encryption key that, once decrypted, will be used to encrypt the provided
 * document's fields.
 */
public final class PlaintextDocument {
  private final Map<String, byte[]> decryptedFields;
  private final String edek;

  public PlaintextDocument(Map<String, byte[]> decryptedFields, String edek) {
    this.decryptedFields = decryptedFields;
    this.edek = edek;
  }

  /** Get the document's encrypted document encryption key (EDEK). */
  public String getEncryptedDocumentEncryptionKey() {
    return edek;
  }

  /** Shorthand method for getEncryptedDocumentEncryptionKey() */
  public String getEdek() {
    return getEncryptedDocumentEncryptionKey();
  }

  /** Get the Map of the plaintext documents fields. */
  public Map<String, byte[]> getDecryptedFields() {
    return decryptedFields;
  }
}
