package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.Closeable;
import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

/**
 * DeterministicTenantSecurityClient class that can be used to deterministically encrypt and decrypt
 * fields.
 *
 * @author IronCore Labs
 */
public final class DeterministicTenantSecurityClient implements Closeable {
  // Use fixed size thread pool for CPU bound operations (crypto ops). Defaults to
  // CPU-cores but configurable on construction.
  private ExecutorService encryptionExecutor;

  private TenantSecurityRequest encryptionService;

  /**
   * Default size of web request thread pool. Defaults to 25.
   */
  public static int DEFAULT_REQUEST_THREADPOOL_SIZE = 25;

  /**
   * Default size of the threadpool used for AES encryptions/decryptions. Defaults to the number of
   * cores on the machine being run on.
   */
  public static int DEFAULT_AES_THREADPOOL_SIZE = Runtime.getRuntime().availableProcessors();

  /**
   * Default timeout in ms for the connection to the TSP.
   */
  public static int DEFAULT_TIMEOUT_MS = 20000;

  /**
   * Constructor for DeterministicTenantSecurityClient class with default values.
   *
   * @param tspDomain Domain where the Tenant Security Proxy is running.
   * @param apiKey Key to use for requests to the Tenant Security Proxy.
   * @throws Exception If the provided domain is invalid.
   */
  public DeterministicTenantSecurityClient(String tspDomain, String apiKey) throws Exception {
    this(tspDomain, apiKey, DEFAULT_REQUEST_THREADPOOL_SIZE, DEFAULT_AES_THREADPOOL_SIZE);
  }

  /**
   * Constructor for DeterministicTenantSecurityClient class that allows for modifying the random
   * number generator used for encryption. Sets a default connect and read timeout of 20s.
   *
   * @param tspDomain Domain where the Tenant Security Proxy is running.
   * @param apiKey Key to use for requests to the Tenant Security Proxy.
   * @param requestThreadSize Number of threads to use for fixed-size web request thread pool
   * @param aesThreadSize Number of threads to use for fixed-size AES operations threadpool
   * @throws Exception If the provided domain is invalid.
   */
  public DeterministicTenantSecurityClient(String tspDomain, String apiKey, int requestThreadSize,
      int aesThreadSize) throws Exception {
    this(tspDomain, apiKey, requestThreadSize, aesThreadSize, DEFAULT_TIMEOUT_MS);
  }

  /**
   * Constructor for DeterministicTenantSecurityClient class that allows for modifying the random
   * number generator used for encryption.
   *
   * @param tspDomain Domain where the Tenant Security Proxy is running.
   * @param apiKey Key to use for requests to the Tenant Security Proxy.
   * @param requestThreadSize Number of threads to use for fixed-size web request thread pool
   * @param aesThreadSize Number of threads to use for fixed-size AES operations threadpool
   * @param timeout Request to TSP read and connect timeout in ms.
   * @throws Exception If the provided domain is invalid.
   */
  public DeterministicTenantSecurityClient(String tspDomain, String apiKey, int requestThreadSize,
      int aesThreadSize, int timeout) throws Exception {
    // Use the URL class to validate the form of the provided TSP domain URL
    new URL(tspDomain);
    if (apiKey == null || apiKey.isEmpty()) {
      throw new IllegalArgumentException("No value provided for apiKey!");
    }
    if (requestThreadSize < 1) {
      throw new IllegalArgumentException(
          "Value provided for request threadpool size must be greater than 0!");
    }
    if (aesThreadSize < 1) {
      throw new IllegalArgumentException(
          "Value provided for AES threadpool size must be greater than 0!");
    }
    if (timeout < 1) {
      throw new IllegalArgumentException("Value provided for timeout must be greater than 0!");
    }

    this.encryptionExecutor = Executors.newFixedThreadPool(aesThreadSize);

    this.encryptionService =
        new TenantSecurityRequest(tspDomain, apiKey, requestThreadSize, timeout);
  }

  DeterministicTenantSecurityClient(ExecutorService aesThreadExecutor,
      TenantSecurityRequest tenantSecurityRequest) throws Exception {
    this.encryptionExecutor = aesThreadExecutor;
    this.encryptionService = tenantSecurityRequest;
  }

  public void close() throws IOException {
    this.encryptionService.close();
    this.encryptionExecutor.shutdown();
  }

  /**
   * Utility method to create a new client instance which returns a CompletableFuture to help handle
   * error situations which can occur on class construction.
   *
   * @param tspDomain Domain where the Tenant Security Proxy is running.
   * @param apiKey Key to use for requests to the Tenant Security Proxy.
   * @return CompletableFuture that resolves in a instance of the DeterministicTenantSecurityClient
   *         class.
   */
  public static CompletableFuture<DeterministicTenantSecurityClient> create(String tspDomain,
      String apiKey) {
    return CompletableFutures
        .tryCatchNonFatal(() -> new DeterministicTenantSecurityClient(tspDomain, apiKey));
  }

  /**
   * Verifies that the tenant for which keys were derived has a primary KMS configuration.
   *
   * @param derivedKeyResponse deriveKey response from the TSP
   * @return CompletableFuture that resolves to the input if successful.
   */
  private CompletableFuture<DeriveKeyResponse> verifyHasPrimaryConfig(
      DeriveKeyResponse deriveKeyResponse) {
    if (deriveKeyResponse.getHasPrimaryConfig()) {
      return CompletableFuture.completedFuture(deriveKeyResponse);
    } else {
      return CompletableFuture.failedFuture(
          new TscException(TenantSecurityErrorCodes.DETERMINISTIC_FIELD_ENCRYPT_FAILED,
              "The provided tenant has no primary KMS configuration"));
    }
  }

  /**
   * Transforms a map of deterministic fields into the map of paths expected by the TSP derive keys
   * endpoint.
   *
   * @param <F> DeterministicPlaintextField or DeterministicEncryptedField
   * @param fields Map from field ID to field that was passed to a batch deterministic operation.
   * @return Map of paths required for the TSP derive keys endpoint
   */
  static <F extends DeterministicPaths> Map<String, String[]> deterministicCollectionToPathMap(
      Map<String, F> fields) {
    Map<String, HashSet<String>> paths = new HashMap<>();
    fields.values().stream().forEach(path -> {
      String secretPath = path.getSecretPath();
      String derivationPath = path.getDerivationPath();
      paths.putIfAbsent(secretPath, new HashSet<>());
      paths.get(secretPath).add(derivationPath);
    });
    return paths.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> {
      HashSet<String> values = entry.getValue();
      return values.toArray(new String[values.size()]);
    }));
  }

  /**
   * Deterministically encrypt the provided field using the tenant's current secret.
   *
   * @param field Field to deterministically encrypt.
   * @param metadata Metadata about the field being encrypted.
   * @return DeterministicEncryptedField which contains the field's paths and encrypted data.
   */
  public CompletableFuture<DeterministicEncryptedField> encryptField(
      DeterministicPlaintextField field, FieldMetadata metadata) {
    Map<String, String[]> paths =
        Collections.singletonMap(field.getSecretPath(), new String[] {field.getDerivationPath()});
    return encryptionService.deriveKey(metadata, paths)
        .thenCompose(deriveKeyResponse -> verifyHasPrimaryConfig(deriveKeyResponse))
        .thenCompose(deriveKeyResponse -> deriveKeyResponse.getDerivedKeys(field.getSecretPath(),
            field.getDerivationPath()))
        .thenCompose(derivedKeys -> DeterministicCryptoUtils.encryptField(field, derivedKeys));
  }

  /**
   * Deterministically encrypt a batch of new fields using the tenant's primary KMS. Supports
   * partial failure and returns a list of fields that were successfully encrypted as well as a list
   * of errors for fields that failed to be encrypted.
   *
   * @param fields Map of field ID to plaintext field to be deterministically encrypted.
   * @param metadata Metadata about the fields being encrypted.
   * @return Collection of successes and failures that occurred during operation. The keys of each
   *         map returned will be the same keys provided in the original fields map.
   */
  public CompletableFuture<BatchResult<DeterministicEncryptedField>> encryptFieldBatch(
      Map<String, DeterministicPlaintextField> fields, FieldMetadata metadata) {
    Map<String, String[]> paths = deterministicCollectionToPathMap(fields);
    return encryptionService.deriveKey(metadata, paths)
        .thenCompose(deriveKeyResponse -> verifyHasPrimaryConfig(deriveKeyResponse))
        .thenApply(deriveKeyResponse -> DeterministicCryptoUtils.encryptFieldBatch(fields,
            deriveKeyResponse, encryptionExecutor));
  }

  /**
   * Decrypt the provided deterministically encrypted field.
   *
   * @param field Deterministically encrypted data to decrypt.
   * @param metadata Metadata about the field being decrypted.
   * @return DeterministicPlaintextField which contains the field's paths and decrypted data.
   */
  public CompletableFuture<DeterministicPlaintextField> decryptField(
      DeterministicEncryptedField field, FieldMetadata metadata) {
    Map<String, String[]> paths =
        Collections.singletonMap(field.getSecretPath(), new String[] {field.getDerivationPath()});
    return encryptionService.deriveKey(metadata, paths)
        .thenCompose(deriveKeyResponse -> deriveKeyResponse.getDerivedKeys(field.getSecretPath(),
            field.getDerivationPath()))
        .thenCompose(derivedKeys -> DeterministicCryptoUtils.decryptField(field, derivedKeys));
  }

  /**
   * Deterministically decrypt a batch of fields using the tenant's KMS that was used for
   * encryption. Supports partial failure and will return both successfully decrypted fields as well
   * as fields that failed to be decrypted.
   *
   * @param fields Map of field ID to deterministically encrypted field to be decrypted.
   * @param metadata Metadata about the fields being decrypted.
   * @return Collection of successes and failures that occurred during operation. The keys of each
   *         map returned will be the same keys provided in the original fields map.
   */
  public CompletableFuture<BatchResult<DeterministicPlaintextField>> decryptFieldBatch(
      Map<String, DeterministicEncryptedField> fields, FieldMetadata metadata) {
    Map<String, String[]> paths = deterministicCollectionToPathMap(fields);
    return encryptionService.deriveKey(metadata, paths)
        .thenApply(deriveKeyResponse -> DeterministicCryptoUtils.decryptFieldBatch(fields,
            deriveKeyResponse, encryptionExecutor));
  }

  /**
   * Decrypt the provided deterministically encrypted field and re-encrypt it with the current
   * tenant secret. This should be called when rotating from one tenant secret to another.
   *
   * @param field Deterministically encrypted data to rotate to the current tenant secret.
   * @param metadata Metadata about the field being rotated.
   * @return DeterministicEncryptedField encrypted using the tenant's current secret.
   */
  public CompletableFuture<DeterministicEncryptedField> rotateField(
      DeterministicEncryptedField field, FieldMetadata metadata) {
    Map<String, String[]> paths =
        Collections.singletonMap(field.getSecretPath(), new String[] {field.getDerivationPath()});
    return encryptionService.deriveKey(metadata, paths)
        .thenCompose(deriveKeyResponse -> verifyHasPrimaryConfig(deriveKeyResponse))
        .thenCompose(deriveKeyResponse -> deriveKeyResponse.getDerivedKeys(field.getSecretPath(),
            field.getDerivationPath()))
        .thenCompose(derivedKeys -> DeterministicCryptoUtils.rotateField(field, derivedKeys));
  }

  /**
   * Determinally decrypt a batch of fields using the tenant's KMS that was used for encryption,
   * then re-encrypt them with the current tenant secret. Supports partial failure and will return
   * both successfully re-encrypted fields as well as fields that failed to be re-encrypted.
   *
   * @param fields Map of field ID to deterministically encrypted field to be rotated.
   * @param metadata Metadata about the fields being rotates.
   * @return Collection of successes and failures that occurred during operation. The keys of each
   *         map returned will be the same keys provided in the original fields map.
   */
  public CompletableFuture<BatchResult<DeterministicEncryptedField>> rotateFieldBatch(
      Map<String, DeterministicEncryptedField> fields, FieldMetadata metadata) {
    Map<String, String[]> paths = deterministicCollectionToPathMap(fields);
    return encryptionService.deriveKey(metadata, paths)
        .thenCompose(deriveKeyResponse -> verifyHasPrimaryConfig(deriveKeyResponse))
        .thenApply(deriveKeyResponse -> DeterministicCryptoUtils.rotateFieldBatch(fields,
            deriveKeyResponse, encryptionExecutor));
  }

  /**
   * Deterministically encrypt the provided field with all current and in-rotation secrets for the
   * tenant. All of the resulting search terms should be used in combination when searching for the
   * field.
   *
   * @param field Field to generate search terms for.
   * @param metadata Metadata about the field to generate search terms for.
   * @return An array of deterministically encrypted fields to use when searching.
   */
  public CompletableFuture<DeterministicEncryptedField[]> generateSearchTerms(
      DeterministicPlaintextField field, FieldMetadata metadata) {
    Map<String, String[]> paths =
        Collections.singletonMap(field.getSecretPath(), new String[] {field.getDerivationPath()});
    return encryptionService.deriveKey(metadata, paths)
        .thenCompose(deriveKeyResponse -> deriveKeyResponse.getDerivedKeys(field.getSecretPath(),
            field.getDerivationPath()))
        .thenCompose(
            derivedKeys -> DeterministicCryptoUtils.generateSearchTerms(field, derivedKeys));
  }

  /**
   * Deterministically encrypt a batch of fields with all current and in-rotation secrets for the
   * tenant. Supports partial failure and will return both successfully encrypted fields as well as
   * fields that failed to be encrypted.
   *
   * @param fields Map of field ID to plaintext field to generate search terms for.
   * @param metadata Metadata about the fields to generate search terms for.
   * @return Collection of successes and failures that occurred during operation. The keys of each
   *         map returned will be the same keys provided in the original fields map.
   */
  public CompletableFuture<BatchResult<DeterministicEncryptedField[]>> generateSearchTermsBatch(
      Map<String, DeterministicPlaintextField> fields, FieldMetadata metadata) {
    Map<String, String[]> paths = deterministicCollectionToPathMap(fields);
    return encryptionService.deriveKey(metadata, paths)
        .thenApply(deriveKeyResponse -> DeterministicCryptoUtils.generateSearchTermsBatch(fields,
            deriveKeyResponse, encryptionExecutor));
  }
}
