package com.ironcorelabs.tenantsecurity.kms.v1;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;
import org.cryptomator.siv.SivMode;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

class DeterministicCryptoUtils {
  static final long MAX_TENANT_SECRET_ID = 4294967295L;

  static final SivMode AES_SIV = new SivMode();

  /**
   * Deterministically encrypt the provided field with the current key from `derivedKeys`.
   */
  static CompletableFuture<DeterministicEncryptedField> encryptField(
      DeterministicPlaintextField field, DerivedKey[] derivedKeys) {
    return CompletableFutures.tryCatchNonFatal(() -> {
      DerivedKey current = null;
      for (DerivedKey key : derivedKeys) {
        if (key.isCurrent()) {
          current = key;
        }
      }
      if (current == null) {
        throw new TscException(TenantSecurityErrorCodes.DETERMINISTIC_FIELD_ENCRYPT_FAILED,
            "No current tenant secret for deterministic encryption.");
      }
      return current;
    }).thenCompose(current -> {
      byte[] dek = current.getDerivedKeyBytes();
      return generateEncryptedFieldHeader(current.getTenantSecretId()).thenCompose(
          header -> encryptBytes(field.getPlaintextField(), dek).thenApply(encryptedBytes -> {
            byte[] encryptedField = ByteBuffer.allocate(header.length + encryptedBytes.length)
                .put(header).put(encryptedBytes).array();
            return new DeterministicEncryptedField(encryptedField, field.getDerivationPath(),
                field.getSecretPath());
          }));
    });
  }

  /**
   * Encode the tenant secret ID as 4 bytes, then attach two bytes of 0s. Fails if the tenant secret
   * ID can't fit into 4 bytes.
   */
  static CompletableFuture<byte[]> generateEncryptedFieldHeader(long tenantSecretId) {
    return CompletableFutures.tryCatchNonFatal(() -> {
      if (tenantSecretId < 0 || tenantSecretId > MAX_TENANT_SECRET_ID) {
        throw new TscException(TenantSecurityErrorCodes.DETERMINISTIC_HEADER_ERROR,
            "Failed to generate header");
      }
      // tenantSecretId is a long because an int would be signed and have a lower maximum
      // value than the TSP could return. But we still only pack it into 4 bytes.
      byte[] longBytes = ByteBuffer.allocate(8).putLong(tenantSecretId).array();
      byte[] bytes = Arrays.copyOfRange(longBytes, 4, 8);
      byte[] paddingBytes = {0, 0};
      return ByteBuffer.allocate(bytes.length + paddingBytes.length).put(bytes).put(paddingBytes)
          .array();
    });

  }

  /**
   * Encrypt the provided bytes with the provided key using AES-256-SIV. associatedData is not used
   * by our deterministic encryption, but is used in our unit tests of AES_SIV encryption.
   */
  static CompletableFuture<byte[]> encryptBytes(byte[] plaintext, byte[] key,
      byte[]... associatedData) {
    return CompletableFutures.tryCatchNonFatal(() -> {
      byte[] macKey = Arrays.copyOfRange(key, 0, key.length / 2);
      byte[] ctrKey = Arrays.copyOfRange(key, key.length / 2, key.length);
      return AES_SIV.encrypt(ctrKey, macKey, plaintext, associatedData);
    });
  }

  /**
   * Decrypt the deterministically encrypted field using the associated tenant secrets contained in
   * `derivedKeys`.
   */
  static CompletableFuture<DeterministicPlaintextField> decryptField(
      DeterministicEncryptedField encryptedField, DerivedKey[] derivedKeys) {
    return decomposeField(encryptedField.getEncryptedField())
        .thenCompose(parts -> CompletableFutures.tryCatchNonFatal(() -> {
          DerivedKey key = null;
          for (DerivedKey derivedKey : derivedKeys) {
            if (derivedKey.getTenantSecretId() == parts.getTenantSecretId()) {
              key = derivedKey;
            }
          }
          if (key == null) {
            throw new TscException(TenantSecurityErrorCodes.DETERMINISTIC_FIELD_DECRYPT_FAILED,
                "Failed deterministic decryption.");
          }
          return key;
        }).thenCompose(key -> decryptBytes(parts.getEncryptedBytes(), key.getDerivedKeyBytes())))
        .thenApply(decrypted -> new DeterministicPlaintextField(decrypted,
            encryptedField.getDerivationPath(), encryptedField.getSecretPath()));
  }


  /**
   * Deconstruct the provided encrypted field into its component parts. Separates the tenant secret
   * ID, padding, and encrypted bytes.
   */
  static CompletableFuture<DeterministicEncryptedFieldParts> decomposeField(
      byte[] encryptedBytesWithHeader) {
    return CompletableFutures.tryCatchNonFatal(() -> {
      if (encryptedBytesWithHeader.length < 6) {
        throw new TscException(TenantSecurityErrorCodes.DETERMINISTIC_HEADER_ERROR,
            "Failed to parse field header");
      }
      byte[] tenantSecretIdBytes = Arrays.copyOfRange(encryptedBytesWithHeader, 0, 4);
      byte[] padding = Arrays.copyOfRange(encryptedBytesWithHeader, 4, 6);
      byte[] encryptedBytes =
          Arrays.copyOfRange(encryptedBytesWithHeader, 6, encryptedBytesWithHeader.length);
      byte[] expectedPadding = {0, 0};
      if (!Arrays.equals(padding, expectedPadding)) {
        throw new TscException(TenantSecurityErrorCodes.DETERMINISTIC_HEADER_ERROR,
            "Failed to parse field header");
      }
      // first 4 bytes represent an unsigned int of the tenantSecretId, but we need to use
      // a long because Java's int is signed.
      long tenantSecretId = ByteBuffer.allocate(8).put(new byte[] {0, 0, 0, 0})
          .put(tenantSecretIdBytes).position(0).getLong();
      return new DeterministicEncryptedFieldParts(tenantSecretId, encryptedBytes);
    });
  }

  /**
   * Attempt to AES-SIV decrypt the provided bytes using the provided key. associatedData is not
   * used by our deterministic decryption, but is used in our unit tests of AES_SIV decryption.
   */
  static CompletableFuture<byte[]> decryptBytes(byte[] encryptedBytes, byte[] key,
      byte[]... associatedData) {
    return CompletableFutures.tryCatchNonFatal(() -> {
      byte[] macKey = Arrays.copyOfRange(key, 0, key.length / 2);
      byte[] ctrKey = Arrays.copyOfRange(key, key.length / 2, key.length);
      return AES_SIV.decrypt(ctrKey, macKey, encryptedBytes, associatedData);
    });
  }

  /**
   * Check if the encrypted field was deterministically encrypted with the current primary. If it
   * is, we can skip the decryption/encryption because it is guaranteed to be equal to its current
   * value.
   */
  static CompletableFuture<Boolean> checkRotationFieldNoOp(
      DeterministicEncryptedField encryptedField, DerivedKey[] derivedKeys) {
    return decomposeField(encryptedField.getEncryptedField()).thenCompose(parts -> {
      long currentKeyId = 0;
      long previousKeyId = 0;
      for (DerivedKey derivedKey : derivedKeys) {
        if (derivedKey.isCurrent()) {
          currentKeyId = derivedKey.getTenantSecretId();
        }
        if (derivedKey.getTenantSecretId() == parts.getTenantSecretId()) {
          previousKeyId = parts.getTenantSecretId();
        }
      }
      if (currentKeyId == 0 || previousKeyId == 0) {
        return CompletableFuture
            .failedFuture(new TscException(TenantSecurityErrorCodes.DETERMINISTIC_ROTATE_FAILED,
                "Failed deterministic rotation of field."));
      } else {
        return CompletableFuture.completedFuture(previousKeyId == currentKeyId);
      }
    });
  }

  /**
   * Decrypt the provided deterministically encrypted field and re-encrypt it with the current
   * tenant secret.
   */
  static CompletableFuture<DeterministicEncryptedField> rotateField(
      DeterministicEncryptedField encryptedField, DerivedKey[] derivedKeys) {
    return checkRotationFieldNoOp(encryptedField, derivedKeys).thenCompose(noOp -> {
      if (noOp) {
        return CompletableFuture.completedFuture(encryptedField);
      } else {
        return decryptField(encryptedField, derivedKeys)
            .thenCompose(decrypted -> encryptField(decrypted, derivedKeys));
      }
    });
  }

  /**
   * Deterministically encrypt the provided field with all current and in-rotation tenant secrets.
   */
  static CompletableFuture<DeterministicEncryptedField[]> generateSearchTerms(
      DeterministicPlaintextField field, DerivedKey[] derivedKeys) {
    List<CompletableFuture<byte[]>> futures = Arrays.asList(derivedKeys).parallelStream()
        .map(derivedKey -> generateEncryptedFieldHeader(derivedKey.getTenantSecretId()).thenCompose(
            header -> encryptBytes(field.getPlaintextField(), derivedKey.getDerivedKeyBytes())
                .thenApply(
                    encryptedBytes -> ByteBuffer.allocate(header.length + encryptedBytes.length)
                        .put(header).put(encryptedBytes).array())))
        .collect(Collectors.toList());
    CompletableFuture<List<byte[]>> combinedFuture = CompletableFutures.sequence(futures);
    return combinedFuture.thenApply(entries -> entries.parallelStream()
        .map(encryptedBytes -> new DeterministicEncryptedField(encryptedBytes,
            field.getDerivationPath(), field.getSecretPath()))
        .toArray(DeterministicEncryptedField[]::new));
  }

  /**
   * Helper function to collect a map of futures into a BatchResult.
   */
  private static <T> BatchResult<T> makeBatchResult(Map<String, CompletableFuture<T>> futures,
      TenantSecurityErrorCodes errorCode) {
    ConcurrentMap<String, T> successes = new ConcurrentHashMap<String, T>();
    ConcurrentMap<String, TenantSecurityException> failures =
        new ConcurrentHashMap<String, TenantSecurityException>();
    futures.entrySet().stream().forEach(entry -> {
      try {
        successes.put(entry.getKey(), entry.getValue().join());
      } catch (Exception e) {
        // `e` is likely a `CompletionException`, so we care about its cause
        if (e.getCause() instanceof TenantSecurityException) {
          failures.put(entry.getKey(), (TenantSecurityException) e.getCause());
        } else {
          failures.put(entry.getKey(), new TscException(errorCode, e));
        }
      }
    });
    return new BatchResult<T>(successes, failures);
  }

  static BatchResult<DeterministicEncryptedField> encryptFieldBatch(
      Map<String, DeterministicPlaintextField> fields, DeriveKeyResponse derivedKeyResponse,
      Executor encryptionExecutor) {
    Map<String, CompletableFuture<DeterministicEncryptedField>> futures =
        fields.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> {
          DeterministicPlaintextField field = entry.getValue();
          return CompletableFuture.supplyAsync(() -> derivedKeyResponse
              .getDerivedKeys(field.getSecretPath(), field.getDerivationPath())
              .thenCompose(derivedKeys -> DeterministicCryptoUtils.encryptField(field, derivedKeys))
              .join(), encryptionExecutor);
        }));
    return makeBatchResult(futures, TenantSecurityErrorCodes.DETERMINISTIC_FIELD_ENCRYPT_FAILED);
  }

  static BatchResult<DeterministicPlaintextField> decryptFieldBatch(
      Map<String, DeterministicEncryptedField> fields, DeriveKeyResponse derivedKeyResponse,
      Executor encryptionExecutor) {
    Map<String, CompletableFuture<DeterministicPlaintextField>> futures =
        fields.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> {
          DeterministicEncryptedField field = entry.getValue();
          return CompletableFuture.supplyAsync(() -> derivedKeyResponse
              .getDerivedKeys(field.getSecretPath(), field.getDerivationPath())
              .thenCompose(derivedKeys -> DeterministicCryptoUtils.decryptField(field, derivedKeys))
              .join(), encryptionExecutor);
        }));
    return makeBatchResult(futures, TenantSecurityErrorCodes.DETERMINISTIC_FIELD_DECRYPT_FAILED);
  }

  static BatchResult<DeterministicEncryptedField> rotateFieldBatch(
      Map<String, DeterministicEncryptedField> fields, DeriveKeyResponse derivedKeyResponse,
      Executor encryptionExecutor) {
    Map<String, CompletableFuture<DeterministicEncryptedField>> futures =
        fields.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> {
          DeterministicEncryptedField field = entry.getValue();
          return CompletableFuture.supplyAsync(() -> derivedKeyResponse
              .getDerivedKeys(field.getSecretPath(), field.getDerivationPath())
              .thenCompose(derivedKeys -> DeterministicCryptoUtils.rotateField(field, derivedKeys))
              .join(), encryptionExecutor);
        }));
    return makeBatchResult(futures, TenantSecurityErrorCodes.DETERMINISTIC_ROTATE_FAILED);
  }

  static BatchResult<DeterministicEncryptedField[]> generateSearchTermsBatch(
      Map<String, DeterministicPlaintextField> fields, DeriveKeyResponse derivedKeyResponse,
      Executor encryptionExecutor) {
    Map<String, CompletableFuture<DeterministicEncryptedField[]>> futures =
        fields.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> {
          DeterministicPlaintextField field = entry.getValue();
          return CompletableFuture.supplyAsync(() -> derivedKeyResponse
              .getDerivedKeys(field.getSecretPath(), field.getDerivationPath())
              .thenCompose(
                  derivedKeys -> DeterministicCryptoUtils.generateSearchTerms(field, derivedKeys))
              .join(), encryptionExecutor);
        }));
    return makeBatchResult(futures,
        TenantSecurityErrorCodes.DETERMINISTIC_GENERATE_SEARCH_TERMS_FAILED);
  }
}
