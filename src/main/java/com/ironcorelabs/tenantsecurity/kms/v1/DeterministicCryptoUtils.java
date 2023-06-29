package com.ironcorelabs.tenantsecurity.kms.v1;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;
import org.cryptomator.siv.SivMode;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.CryptoException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

class DeterministicCryptoUtils {
  static final long MAX_TENANT_SECRET_ID = 4294967295L;

  static final SivMode AES_SIV = new SivMode();

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
        throw new CryptoException("No current tenant secret for deterministic encryption.");
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

  static CompletableFuture<byte[]> generateEncryptedFieldHeader(long tenantSecretId) {
    return CompletableFutures.tryCatchNonFatal(() -> {
      if (tenantSecretId < 0 || tenantSecretId > MAX_TENANT_SECRET_ID) {
        throw new CryptoException("Failed to generate header.");
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

  static CompletableFuture<byte[]> encryptBytes(byte[] plaintext, byte[] key,
      byte[]... associatedData) {
    return CompletableFutures.tryCatchNonFatal(() -> {
      byte[] macKey = Arrays.copyOfRange(key, 0, key.length / 2);
      byte[] ctrKey = Arrays.copyOfRange(key, key.length / 2, key.length);
      return AES_SIV.encrypt(ctrKey, macKey, plaintext, associatedData);
    });
  }

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
            throw new CryptoException("Failed deterministic decryption.");
          }
          return key;
        }).thenCompose(key -> decryptBytes(parts.getEncryptedBytes(), key.getDerivedKeyBytes())))
        .thenApply(decrypted -> new DeterministicPlaintextField(decrypted,
            encryptedField.getDerivationPath(), encryptedField.getSecretPath()));
  }

  static CompletableFuture<DeterministicEncryptedFieldParts> decomposeField(
      byte[] encryptedBytesWithHeader) {
    return CompletableFutures.tryCatchNonFatal(() -> {
      if (encryptedBytesWithHeader.length < 6) {
        throw new CryptoException("Failed to parse field header.");
      }
      byte[] tenantSecretIdBytes = Arrays.copyOfRange(encryptedBytesWithHeader, 0, 4);
      byte[] padding = Arrays.copyOfRange(encryptedBytesWithHeader, 4, 6);
      byte[] encryptedBytes =
          Arrays.copyOfRange(encryptedBytesWithHeader, 6, encryptedBytesWithHeader.length);
      byte[] expectedPadding = {0, 0};
      if (!Arrays.equals(padding, expectedPadding)) {
        throw new CryptoException("Failed to parse field header.");
      }
      // first 4 bytes represent an unsigned int of the tenantSecretId, but we need to use
      // a long because Java's int is signed.
      long tenantSecretId = ByteBuffer.allocate(8).put(new byte[] {0, 0, 0, 0})
          .put(tenantSecretIdBytes).position(0).getLong();
      return new DeterministicEncryptedFieldParts(tenantSecretId, encryptedBytes);
    });
  }

  static CompletableFuture<byte[]> decryptBytes(byte[] encryptedBytes, byte[] key,
      byte[]... associatedData) {
    return CompletableFutures.tryCatchNonFatal(() -> {
      byte[] macKey = Arrays.copyOfRange(key, 0, key.length / 2);
      byte[] ctrKey = Arrays.copyOfRange(key, key.length / 2, key.length);
      return AES_SIV.decrypt(ctrKey, macKey, encryptedBytes, associatedData);
    });
  }

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
            .failedFuture(new CryptoException("Failed deterministic rotation of field."));
      } else {
        return CompletableFuture.completedFuture(previousKeyId == currentKeyId);
      }
    });
  }

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
        .collect(Collectors.toList()).toArray(new DeterministicEncryptedField[entries.size()]));
  }

  static BatchResult<DeterministicEncryptedField> encryptBatch(
      Map<String, DeterministicPlaintextField> fields, DeriveKeyResponse derivedKeyResponse) {
    ConcurrentMap<String, DeterministicEncryptedField> successes =
        new ConcurrentHashMap<String, DeterministicEncryptedField>();
    ConcurrentMap<String, TenantSecurityException> failures =
        new ConcurrentHashMap<String, TenantSecurityException>();

    fields.entrySet().parallelStream().forEach(entry -> {
      DeterministicPlaintextField field = entry.getValue();
      CompletableFuture<DeterministicEncryptedField> encryptedFuture = derivedKeyResponse
          .getDerivedKeys(field.getSecretPath(), field.getDerivationPath())
          .thenCompose(derivedKeys -> DeterministicCryptoUtils.encryptField(field, derivedKeys));
      try {
        successes.put(entry.getKey(), encryptedFuture.join());
      } catch (Exception e) {
        failures.put(entry.getKey(),
            new TscException(TenantSecurityErrorCodes.DETERMINISTIC_FIELD_ENCRYPT_FAILED, e));
      }
    });
    return new BatchResult<DeterministicEncryptedField>(successes, failures);
  }


  static BatchResult<DeterministicPlaintextField> decryptBatch(
      Map<String, DeterministicEncryptedField> fields, DeriveKeyResponse derivedKeyResponse) {
    ConcurrentMap<String, DeterministicPlaintextField> successes =
        new ConcurrentHashMap<String, DeterministicPlaintextField>();
    ConcurrentMap<String, TenantSecurityException> failures =
        new ConcurrentHashMap<String, TenantSecurityException>();

    fields.entrySet().parallelStream().forEach(entry -> {
      DeterministicEncryptedField field = entry.getValue();
      CompletableFuture<DeterministicPlaintextField> decryptedFuture = derivedKeyResponse
          .getDerivedKeys(field.getSecretPath(), field.getDerivationPath())
          .thenCompose(derivedKeys -> DeterministicCryptoUtils.decryptField(field, derivedKeys));
      try {
        successes.put(entry.getKey(), decryptedFuture.join());
      } catch (Exception e) {
        failures.put(entry.getKey(),
            new TscException(TenantSecurityErrorCodes.DETERMINISTIC_FIELD_DECRYPT_FAILED, e));
      }
    });
    return new BatchResult<DeterministicPlaintextField>(successes, failures);
  }
  // TODO: make this function return CompletableFuture<DeterministicPlaintextField> and then outside
  // do .supplyAsync on a separate function that does the .join?
}
