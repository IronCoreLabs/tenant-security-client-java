package com.ironcorelabs.tenantsecurity.kms.v1;

import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.stream.Collectors;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

/**
 * Package-private static helper for field-level encryption/decryption and batch result aggregation.
 */
final class DocumentCryptoOps {

  private DocumentCryptoOps() {}

  /**
   * Encrypt all fields in the document using the provided DEK. Each field is encrypted in parallel
   * on the provided executor.
   */
  static CompletableFuture<EncryptedDocument> encryptFields(Map<String, byte[]> document,
      DocumentMetadata metadata, byte[] dek, String edek, ExecutorService executor,
      SecureRandom secureRandom) {
    Map<String, CompletableFuture<byte[]>> encryptOps = document.entrySet().stream()
        .collect(Collectors.toMap(Map.Entry::getKey, entry -> CompletableFuture.supplyAsync(
            () -> CryptoUtils.encryptBytes(entry.getValue(), metadata, dek, secureRandom).join(),
            executor)));

    return CompletableFutures.tryCatchNonFatal(() -> {
      Map<String, byte[]> encryptedBytes = encryptOps.entrySet().stream()
          .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().join()));
      return new EncryptedDocument(encryptedBytes, edek);
    });
  }

  /**
   * Decrypt all fields in the document using the provided DEK. Each field is decrypted in parallel
   * on the provided executor.
   */
  static CompletableFuture<PlaintextDocument> decryptFields(Map<String, byte[]> document,
      byte[] dek, String edek, ExecutorService executor) {
    Map<String, CompletableFuture<byte[]>> decryptOps = document.entrySet().stream()
        .collect(Collectors.toMap(Map.Entry::getKey, entry -> CompletableFuture.supplyAsync(
            () -> CryptoUtils.decryptDocument(entry.getValue(), dek).join(), executor)));

    return CompletableFutures.tryCatchNonFatal(() -> {
      Map<String, byte[]> decryptedBytes = decryptOps.entrySet().stream()
          .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().join()));
      return new PlaintextDocument(decryptedBytes, edek);
    });
  }

  /**
   * Collect a map from String to CompletableFuture<T> into a BatchResult. Futures that complete
   * exceptionally are wrapped in TscExceptions with the provided errorCode.
   */
  static <T> BatchResult<T> cryptoOperationToBatchResult(
      ConcurrentMap<String, CompletableFuture<T>> operationResults,
      TenantSecurityErrorCodes errorCode) {
    ConcurrentMap<String, T> successes = new ConcurrentHashMap<>(operationResults.size());
    ConcurrentMap<String, TenantSecurityException> failures = new ConcurrentHashMap<>();
    operationResults.entrySet().parallelStream().forEach(entry -> {
      try {
        T doc = entry.getValue().join();
        successes.put(entry.getKey(), doc);
      } catch (Exception e) {
        failures.put(entry.getKey(), new TscException(errorCode, e));
      }
    });
    return new BatchResult<T>(successes, failures);
  }
}
