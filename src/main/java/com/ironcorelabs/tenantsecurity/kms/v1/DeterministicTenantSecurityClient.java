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
import com.ironcorelabs.tenantsecurity.kms.v1.exception.CryptoException;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

/**
 * TenantSecurityClient class that can be used to encrypt and decrypt documents.
 *
 * @author IronCore Labs
 */
public final class DeterministicTenantSecurityClient implements Closeable {
  // Use fixed size thread pool for CPU bound operations (crypto ops). Defaults to
  // CPU-cores but configurable on construction.
  private ExecutorService encryptionExecutor;

  private TenantSecurityRequest encryptionService;

  /**
   * Default size of web request thread pool. Value value is 25.
   */
  public static int DEFAULT_REQUEST_THREADPOOL_SIZE = 25;

  /**
   * Default size of the threadpool used for AES encryptions/decryptions. Defaults to the number of
   * cores on the machine being run on.
   */
  public static int DEFAULT_AES_THREADPOOL_SIZE = Runtime.getRuntime().availableProcessors();

  /**
   * Constructor for TenantSecurityClient class with default values.
   *
   * @param tspDomain Domain where the Tenant Security Proxy is running.
   * @param apiKey Key to use for requests to the Tenant Security Proxy.
   * @throws Exception If the provided domain is invalid.
   */
  public DeterministicTenantSecurityClient(String tspDomain, String apiKey) throws Exception {
    this(tspDomain, apiKey, DEFAULT_REQUEST_THREADPOOL_SIZE, DEFAULT_AES_THREADPOOL_SIZE);
  }

  /**
   * Constructor for TenantSecurityClient class that allows for modifying the random number
   * generator used for encryption. Sets a default connect and read timeout of 20s.
   *
   * @param tspDomain Domain where the Tenant Security Proxy is running.
   * @param apiKey Key to use for requests to the Tenant Security Proxy.
   * @param requestThreadSize Number of threads to use for fixed-size web request thread pool
   * @param aesThreadSize Number of threads to use for fixed-size AES operations threadpool
   * @throws Exception If the provided domain is invalid.
   */
  public DeterministicTenantSecurityClient(String tspDomain, String apiKey, int requestThreadSize,
      int aesThreadSize) throws Exception {
    this(tspDomain, apiKey, requestThreadSize, aesThreadSize, 20000);
  }

  /**
   * Constructor for TenantSecurityClient class that allows for modifying the random number
   * generator used for encryption.
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

    this.encryptionExecutor = Executors.newFixedThreadPool(aesThreadSize);

    this.encryptionService =
        new TenantSecurityRequest(tspDomain, apiKey, requestThreadSize, timeout);
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
   * @return CompletableFuture that resolves in a instance of the TenantSecurityClient class.
   */
  public static CompletableFuture<DeterministicTenantSecurityClient> create(String tspDomain,
      String apiKey) {
    return CompletableFutures
        .tryCatchNonFatal(() -> new DeterministicTenantSecurityClient(tspDomain, apiKey));
  }

  private CompletableFuture<DeriveKeyResponse> verifyHasPrimaryConfig(
      DeriveKeyResponse derivedKeys) {
    if (derivedKeys.getHasPrimaryConfig()) {
      return CompletableFuture.completedFuture(derivedKeys);
    } else {
      return CompletableFuture.failedFuture(
          new CryptoException("The provided tenant has no primary KMS configuration"));
    }
  }


  public CompletableFuture<DeterministicEncryptedField> encrypt(DeterministicPlaintextField field,
      DocumentMetadata metadata) {
    String[] derivationPaths = {field.getDerivationPath()};
    Map<String, String[]> paths = Collections.singletonMap(field.getSecretPath(), derivationPaths);
    return encryptionService.deriveKey(metadata, paths)
        .thenCompose(deriveKeyResponse -> verifyHasPrimaryConfig(deriveKeyResponse))
        .thenCompose(deriveKeyResponse -> deriveKeyResponse.getDerivedKeys(field.getSecretPath(),
            field.getDerivationPath()))
        .thenCompose(derivedKeys -> DeterministicCryptoUtils.encryptField(field, derivedKeys));
  }

  public <F extends DeterministicPaths> Map<String, String[]> deterministicCollectionToPathMap(
      Map<String, F> fields) {
    HashMap<String, HashSet<String>> paths = new HashMap<String, HashSet<String>>();
    fields.values().stream().forEach(path -> {
      String secretPath = path.getSecretPath();
      String derivationPath = path.getDerivationPath();
      paths.putIfAbsent(secretPath, new HashSet<String>());
      paths.get(secretPath).add(derivationPath);
    });
    return paths.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> {
      HashSet<String> values = entry.getValue();
      return values.toArray(new String[values.size()]);
    }));
  }

  public CompletableFuture<BatchResult<DeterministicEncryptedField>> encryptBatch(
      Map<String, DeterministicPlaintextField> fields, DocumentMetadata metadata) {
    Map<String, String[]> paths = deterministicCollectionToPathMap(fields);
    return encryptionService.deriveKey(metadata, paths).thenApplyAsync(
        deriveKeyResponse -> DeterministicCryptoUtils.encryptBatch(fields, deriveKeyResponse),
        encryptionExecutor);
  }

  public CompletableFuture<DeterministicPlaintextField> decrypt(DeterministicEncryptedField field,
      DocumentMetadata metadata) {
    String[] derivationPaths = {field.getDerivationPath()};
    Map<String, String[]> paths = Collections.singletonMap(field.getSecretPath(), derivationPaths);
    return encryptionService.deriveKey(metadata, paths)
        .thenCompose(deriveKeyResponse -> verifyHasPrimaryConfig(deriveKeyResponse))
        .thenCompose(deriveKeyResponse -> deriveKeyResponse.getDerivedKeys(field.getSecretPath(),
            field.getDerivationPath()))
        .thenCompose(derivedKeys -> DeterministicCryptoUtils.decryptField(field, derivedKeys));
  }

  public CompletableFuture<BatchResult<DeterministicPlaintextField>> decryptBatch(
      Map<String, DeterministicEncryptedField> fields, DocumentMetadata metadata) {
    Map<String, String[]> paths = deterministicCollectionToPathMap(fields);
    return encryptionService.deriveKey(metadata, paths).thenApplyAsync(
        deriveKeyResponse -> DeterministicCryptoUtils.decryptBatch(fields, deriveKeyResponse),
        encryptionExecutor);
  }
}
