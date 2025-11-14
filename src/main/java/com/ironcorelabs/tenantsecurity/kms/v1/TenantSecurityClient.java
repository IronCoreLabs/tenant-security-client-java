package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TscException;
import com.ironcorelabs.tenantsecurity.logdriver.v1.EventMetadata;
import com.ironcorelabs.tenantsecurity.logdriver.v1.SecurityEvent;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

/**
 * TenantSecurityClient class that can be used to encrypt and decrypt documents.
 *
 * @author IronCore Labs
 */
public final class TenantSecurityClient implements Closeable {
  private final SecureRandom secureRandom;

  // Use fixed size thread pool for CPU bound operations (crypto ops). Defaults to
  // CPU-cores but configurable on construction.
  private ExecutorService encryptionExecutor;

  private TenantSecurityRequest encryptionService;

  private DeterministicTenantSecurityClient deterministicClient;

  private TenantSecurityClient(Builder builder) throws Exception {
    // Validate domain
    TenantSecurityClient.checkUrlForm(builder.tspDomain, builder.allowInsecureHttp);

    if (builder.apiKey == null || builder.apiKey.isEmpty()) {
      throw new IllegalArgumentException("No value provided for apiKey!");
    }
    if (builder.randomGen == null) {
      throw new IllegalArgumentException("No value provided for random number generator!");
    }
    if (builder.requestThreadSize < 1) {
      throw new IllegalArgumentException(
          "Value provided for request threadpool size must be greater than 0!");
    }
    if (builder.aesThreadSize < 1) {
      throw new IllegalArgumentException(
          "Value provided for AES threadpool size must be greater than 0!");
    }
    if (builder.timeout < 1) {
      throw new IllegalArgumentException("Value provided for timeout must be greater than 0!");
    }

    this.encryptionExecutor = Executors.newFixedThreadPool(builder.aesThreadSize);
    this.encryptionService = new TenantSecurityRequest(builder.tspDomain, builder.apiKey,
        builder.requestThreadSize, builder.timeout);
    this.deterministicClient =
        new DeterministicTenantSecurityClient(this.encryptionExecutor, this.encryptionService);

    Security.setProperty("crypto.policy", "unlimited");
    this.secureRandom = builder.randomGen;
  }

  /**
   * Ensures that the url is valid and if allowInsecureHttp is false that the tsp url must be https.
   * Will throw if the URL isn't valid or if https is enforced and not provided.
   *
   * @param url The Url to check
   * @param allowInsecureHttp If normal http should be allowed..
   */
  private static void checkUrlForm(String url, boolean allowInsecureHttp) {
    try {
      URL parsed = new URL(url);
      String protocol = parsed.getProtocol();
      if (!allowInsecureHttp && !"https".equalsIgnoreCase(protocol)) {
        throw new IllegalArgumentException("Insecure HTTP URL not allowed: " + url);
      }
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException("Invalid URL: " + url, e);
    }
  }

  public static class Builder {

    /**
     * Default size of web request thread pool. Defaults to 25.
     */
    public static int DEFAULT_REQUEST_THREADPOOL_SIZE = 25;

    /**
     * Default size of the threadpool used for AES encryptions/decryptions. Defaults to the number
     * of cores on the machine being run on.
     */
    public static int DEFAULT_AES_THREADPOOL_SIZE = Runtime.getRuntime().availableProcessors();

    /**
     * Default timeout in ms for the connection to the TSP.
     */
    public static int DEFAULT_TIMEOUT_MS = 20000;

    private final String tspDomain;
    private final String apiKey;

    private int requestThreadSize = DEFAULT_REQUEST_THREADPOOL_SIZE;
    private int aesThreadSize = DEFAULT_AES_THREADPOOL_SIZE;
    private int timeout = DEFAULT_TIMEOUT_MS;
    private boolean allowInsecureHttp = false;
    // If this is null when build is called we set it to the default. Don't set it here
    // in case the default isn't available on their OS.
    private SecureRandom randomGen = null;

    /**
     * Builder for TenantSecurityClient class.
     *
     * @param tspDomain Domain where the Tenant Security Proxy is running.
     * @param apiKey Key to use for requests to the Tenant Security Proxy.
     * @param tspDomain
     * @param apiKey
     */
    public Builder(String tspDomain, String apiKey) {
      this.tspDomain = tspDomain;
      this.apiKey = apiKey;
    }

    /**
     * Sets the web request pool size. Defaults to DEFAULT_REQUEST_THREADPOOL_SIZE.
     *
     * @param size Number of threads to use for fixed-size web request thread pool.
     * @return The builder
     */
    public Builder requestThreadSize(int size) {
      this.requestThreadSize = size;
      return this;
    }

    /**
     * Sets the number of threads to use for fixed-size AES operations threadpool. Defaults to
     * DEFAULT_AES_THREADPOOL_SIZE
     *
     * @param size The size of the aes thread pool.
     * @return The builder
     */
    public Builder aesThreadSize(int size) {
      this.aesThreadSize = size;
      return this;
    }

    /**
     * Sets the timeout in milliseconds for communicating with the TSP.
     *
     * @param timeout Timeout in milliseconds for the TSP requests.
     * @return The builder
     */
    public Builder timeoutMs(int timeout) {
      this.timeout = timeout;
      return this;
    }

    /**
     * Sets the random number generator. This should be set with care as the generator must be
     * cryptographically secure. Defaults to "NativePRNGNonBlocking"
     *
     * @param random A new random number generator to use.
     * @return The builder
     */
    public Builder random(SecureRandom random) {
      this.randomGen = random;
      return this;
    }

    /**
     * Sets allowInsecureHttp. Defaults to false.
     *
     * @param allow If the TSP is allowed to be reachable via http.
     * @return The builder
     */
    public Builder allowInsecureHttp(boolean allow) {
      this.allowInsecureHttp = allow;
      return this;
    }

    /**
     * Construct the TenantSecurityClient fron the builder.
     *
     * @return The newly constructed TenantSecurityClient.
     * @throws Exception If the tsp url isn't valid or if HTTPS is required and not provided.
     */
    public TenantSecurityClient build() throws Exception {
      // Check this here in case they don't have support for NativePRNGNonBlocking.
      if (this.randomGen == null) {
        this.randomGen = SecureRandom.getInstance("NativePRNGNonBlocking");
      }
      return new TenantSecurityClient(this);
    }
  }

  /**
   * Constructor for TenantSecurityClient class that allows for modifying the random number
   * generator used for encryption.
   *
   * @param tspDomain Domain where the Tenant Security Proxy is running.
   * @param apiKey Key to use for requests to the Tenant Security Proxy.
   * @param requestThreadSize Number of threads to use for fixed-size web request thread pool
   * @param aesThreadSize Number of threads to use for fixed-size AES operations threadpool
   * @param randomGen Instance of SecureRandom to use for PRNG when performing encryption
   *        operations.
   * @param timeout Request to TSP read and connect timeout in ms.
   * @throws Exception If the provided domain is invalid or the provided SecureRandom instance is
   *         not set.
   */
  public TenantSecurityClient(String tspDomain, String apiKey, int requestThreadSize,
      int aesThreadSize, SecureRandom randomGen, int timeout, boolean allowInsecureHttp)
      throws Exception {
    // Use the URL class to validate the form of the provided TSP domain URL
    new URL(tspDomain);
    if (apiKey == null || apiKey.isEmpty()) {
      throw new IllegalArgumentException("No value provided for apiKey!");
    }
    if (randomGen == null) {
      throw new IllegalArgumentException("No value provided for random number generator!");
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
    this.deterministicClient =
        new DeterministicTenantSecurityClient(this.encryptionExecutor, this.encryptionService);

    this.secureRandom = randomGen;
  }

  public void close() throws IOException {
    this.encryptionService.close();
    this.encryptionExecutor.shutdown();
  }

  /**
   * Get a DeterministicTenantSecurityClient to deterministically encrypt and decrypt fields. The
   * deterministic client inherits the configuration of this client, using the same thread pools for
   * requests and AES operations as this client. To use a different configuration or pools, you can
   * construct a DeterministicTenantSecurityClient directly.
   */
  public DeterministicTenantSecurityClient getDeterministicClient() {
    return deterministicClient;
  }

  /**
   * Utility method to create a new client instance which returns a CompletableFuture to help handle
   * error situations which can occur on class construction.
   *
   * @param tspDomain Domain where the Tenant Security Proxy is running.
   * @param apiKey Key to use for requests to the Tenant Security Proxy.
   * @return CompletableFuture that resolves in a instance of the TenantSecurityClient class.
   */
  public static CompletableFuture<TenantSecurityClient> create(String tspDomain, String apiKey) {
    return CompletableFutures
        .tryCatchNonFatal(() -> new TenantSecurityClient.Builder(tspDomain, apiKey).build());
  }

  /**
   * Encrypt the provided map of fields using the provided encryption key (DEK) and return the
   * resulting encrypted document.
   */
  private CompletableFuture<EncryptedDocument> encryptFields(Map<String, byte[]> document,
      DocumentMetadata metadata, byte[] dek, String edek) {
    // First, iterate over the map of documents and kick off the encrypt operation
    // Future for each one. As part of doing this, we kick off the operation on to
    // another thread so they run in parallel.
    Map<String, CompletableFuture<byte[]>> encryptOps =
        document.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry -> {
          // Do this mapping in the .collect because we can just map the value. If we
          // tried doing this in a .map above the .collect we'd have to return another
          // Entry which is more complicated
          return CompletableFuture.supplyAsync(() -> CryptoUtils
              .encryptBytes(entry.getValue(), metadata, dek, this.secureRandom).join(),
              encryptionExecutor);
        }));

    return CompletableFutures.tryCatchNonFatal(() -> {
      // Now iterate over our map of keys to Futures and call join on all of them. We
      // do this in a separate stream() because if we called join() above it'd block
      // each iteration and cause them to be run in CompletableFutures.sequence.
      Map<String, byte[]> encryptedBytes = encryptOps.entrySet().stream()
          .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().join()));
      return new EncryptedDocument(encryptedBytes, edek);
    });
  }

  /**
   * Encrypt the provided map of encrypted fields using the provided DEK and return the resulting
   * decrypted document.
   */
  private CompletableFuture<PlaintextDocument> decryptFields(Map<String, byte[]> document,
      byte[] dek, String edek) {
    // First map over the encrypted document map and convert the values from
    // encrypted bytes to Futures of decrypted bytes. Make sure each decrypt happens
    // on it's own thread to run them in parallel.
    Map<String, CompletableFuture<byte[]>> decryptOps =
        document.entrySet().stream().collect(Collectors.toMap(Map.Entry::getKey, entry ->
        // Do this mapping in the .collect because we can just map the value. If we
        // tried doing this in a .map above the .collect we'd have to return another
        // Entry which is more complicated
        CompletableFuture.supplyAsync(
            () -> CryptoUtils.decryptDocument(entry.getValue(), dek).join(), encryptionExecutor)));
    // Then iterate over the map of Futures and join them to get the decrypted bytes
    // out. Return the map with the same keys passed in, but the values will now be
    // decrypted.
    return CompletableFutures.tryCatchNonFatal(() -> {
      Map<String, byte[]> decryptedBytes = decryptOps.entrySet().stream()
          .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().join()));
      return new PlaintextDocument(decryptedBytes, edek);
    });
  }

  /**
   * Given a map of document IDs to plaintext bytes to encrypt and a map of document IDs to a fresh
   * DEK, iterate over the DEKs and encrypt the document with the same key.
   */
  private BatchResult<EncryptedDocument> encryptBatchOfDocuments(
      Map<String, Map<String, byte[]>> documents, DocumentMetadata metadata,
      ConcurrentMap<String, WrappedDocumentKey> dekList) {
    ConcurrentMap<String, CompletableFuture<EncryptedDocument>> encryptResults =
        dekList.entrySet().parallelStream()
            .collect(Collectors.toConcurrentMap(ConcurrentMap.Entry::getKey, dekResult -> {
              String documentId = dekResult.getKey();
              WrappedDocumentKey documentKeys = dekResult.getValue();
              return encryptFields(documents.get(documentId), metadata, documentKeys.getDekBytes(),
                  documentKeys.getEdek());
            }));
    return cryptoOperationToBatchResult(encryptResults,
        TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED);
  }

  /**
   * Collect a map from String to CompletableFuture<T> into a BatchResult. T will be either an
   * EncryptedDocument or a PlaintextDocument. CompletableFuture failures will be wrapped in
   * TscExceptions with the provided errorCode and the underlying Throwable cause.
   */
  private <T> BatchResult<T> cryptoOperationToBatchResult(
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

  /**
   * Given a map of document IDs to previously encrypted plaintext documents to re-encrypt and a map
   * of document IDs to the documents DEK, iterate over the DEKs and re-encrypt the document with
   * the same key.
   */
  private BatchResult<EncryptedDocument> encryptExistingBatchOfDocuments(
      Map<String, PlaintextDocument> documents, DocumentMetadata metadata,
      ConcurrentMap<String, UnwrappedDocumentKey> dekList) {
    ConcurrentMap<String, CompletableFuture<EncryptedDocument>> encryptResults =
        dekList.entrySet().parallelStream()
            .collect(Collectors.toConcurrentMap(ConcurrentMap.Entry::getKey, dekResult -> {
              String documentId = dekResult.getKey();
              UnwrappedDocumentKey documentKeys = dekResult.getValue();
              return encryptFields(documents.get(documentId).getDecryptedFields(), metadata,
                  documentKeys.getDekBytes(), documents.get(documentId).getEdek());
            }));
    return cryptoOperationToBatchResult(encryptResults,
        TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED);
  }

  /**
   * Given a map of document IDs to EncryptedDocument to decrypt and a map of document IDs to a DEK
   * iterate over the DEKs and decrypt the document with the same key.
   */
  private BatchResult<PlaintextDocument> decryptBatchDocuments(
      Map<String, EncryptedDocument> documents,
      ConcurrentMap<String, UnwrappedDocumentKey> dekList) {
    ConcurrentMap<String, CompletableFuture<PlaintextDocument>> decryptResults =
        dekList.entrySet().parallelStream()
            .collect(Collectors.toConcurrentMap(ConcurrentMap.Entry::getKey, dekResult -> {
              String documentId = dekResult.getKey();
              UnwrappedDocumentKey documentKeys = dekResult.getValue();
              EncryptedDocument eDoc = documents.get(documentId);
              return decryptFields(eDoc.getEncryptedFields(), documentKeys.getDekBytes(),
                  eDoc.getEdek());
            }));
    return cryptoOperationToBatchResult(decryptResults,
        TenantSecurityErrorCodes.DOCUMENT_DECRYPT_FAILED);
  }

  /**
   * Given a map of document IDs to TSP error responses which have an error code and a message,
   * convert the map to a map of the same document ID but to a TenantSecurityException.
   */
  private ConcurrentMap<String, TenantSecurityException> getBatchFailures(
      ConcurrentMap<String, ErrorResponse> failures) {
    return failures.entrySet().parallelStream()
        .collect(Collectors.toConcurrentMap(ConcurrentMap.Entry::getKey, failure -> {
          ErrorResponse errorResponse = failure.getValue();
          return errorResponse.toTenantSecurityException(0);
        }));
  }

  /**
   * Add a map of TSP failures to the provided BatchResult. The batch successes will be unchanged.
   *
   * @param <T> Success type for BatchResult. Should be EncryptedDocument or PlaintextDocument
   * @param batchResult Result from batch operation like `encryptBatchOfDocuments`
   * @param tspFailures Failures provided by the TSP when calling a batch endpoint
   * @return A new BatchResult where the failures are a combination of the original failures and the
   *         TSP-provided failures.
   */
  protected <T> BatchResult<T> addTspFailuresToBatchResult(BatchResult<T> batchResult,
      Map<String, ErrorResponse> tspFailures) {
    ConcurrentMap<String, TenantSecurityException> tscExceptions =
        getBatchFailures(new ConcurrentHashMap<>(tspFailures));
    ConcurrentMap<String, TenantSecurityException> combinedExceptions = Stream
        .concat(batchResult.getFailures().entrySet().parallelStream(),
            tscExceptions.entrySet().parallelStream())
        .collect(Collectors.toConcurrentMap(Map.Entry::getKey, Map.Entry::getValue));
    return new BatchResult<T>(batchResult.getSuccesses(), combinedExceptions);
  }

  /**
   * Encrypt the bytes in input and write it to output. A new key will be wrapped using the TSP. The
   * returned value contains the edek needed to decrypt the resulting stream.
   *
   * @param input The input stream of bytes to encrypt.
   * @param output The output stream to write encrypted bytes to.
   * @param metadata Metadata about the document being encrypted.
   * @return The edek which can be used to decrypt the resulting stream
   */
  public CompletableFuture<StreamingResponse> encryptStream(InputStream input, OutputStream output,
      DocumentMetadata metadata) {
    return this.encryptionService.wrapKey(metadata).thenApplyAsync(
        wrapResponse -> CryptoUtils
            .encryptStreamInternal(wrapResponse.getDekBytes(), metadata, input, output,
                this.secureRandom)
            .thenApply(unused -> new StreamingResponse(wrapResponse.getEdek())).join(),
        encryptionExecutor);
  }

  /**
   * Decrypt the bytes that are represented by input using the key contained inside the edek. No
   * bytes will be written to the output stream until the entire document has been decrypted. This
   * means that even though the data is streamed in the decrypted data will be cached in memory
   * until the tag has been verified. Once the GCM tag has been reached and verified, this function
   * will return. If there is a problem with the document represented by input or a problem
   * unwrapping the edek the returned CompletableFuture will return an exception instead.
   *
   * @param edek The encrypted dek which should be unwrapped by the TSP.
   * @param input A stream representing the encrypted document.
   * @param output An output stream to write the decrypted document to. Note that this output should
   *        not be used until after the future exits successfully because the GCM tag is not fully
   *        verified until that time.
   * @param metadata Metadata about the document being encrypted.
   * @return Future which will complete when input has been decrypted.
   */
  public CompletableFuture<Void> decryptStream(String edek, InputStream input, OutputStream output,
      DocumentMetadata metadata) {
    return this.encryptionService.unwrapKey(edek, metadata).thenApplyAsync(
        dek -> CryptoUtils.decryptStreamInternal(dek, input, output).join(), encryptionExecutor);
  }

  /**
   * Encrypt the provided document. Documents are provided as a map of fields from the document
   * id/name (String) to bytes (byte[]). Uses the Tenant Security Proxy to generate a new document
   * encryption key (DEK), encrypt that key (EDEK) and then uses the DEK to encrypt all of the
   * provided document fields. Returns an EncryptedDocument which contains a Map from each fields
   * id/name to encrypted bytes as well as the EDEK and discards the DEK.
   *
   * @param document Document to encrypt. Each field in the provided document will be encrypted with
   *        the same key.
   * @param metadata Metadata about the document being encrypted.
   * @return Encrypted document and base64 encrypted document key (EDEK) wrapped in a
   *         EncryptedResult class.
   */
  public CompletableFuture<EncryptedDocument> encrypt(Map<String, byte[]> document,
      DocumentMetadata metadata) {
    return this.encryptionService.wrapKey(metadata)
        .thenComposeAsync(newDocumentKeys -> encryptFields(document, metadata,
            newDocumentKeys.getDekBytes(), newDocumentKeys.getEdek()));
  }

  /**
   * Encrypt the provided document reusing an existing encrypted document encryption key (EDEK).
   * Makes a call out to the Tenant Security Proxy to decrypt the EDEK and then uses the resulting
   * key (DEK) to encrypt the document. This allows callers to update/re-encrypt data that has
   * already been encrypted with an existing key. For example, if multiple columns in a DB row are
   * all encrypted to the same key and one of those columns needs to be updated, this method allows
   * the caller to update a single column without having to re-encrypt every field in the row with a
   * new key.
   *
   * @param document PlaintextDocument which contains the encrypted document key (EDEK) as well as
   *        the Map of bytes to encrypt.
   * @param metadata Metadata about the document being encrypted.
   * @return EncryptedDocument which contains a map of encrypted bytes and base64 encrypted document
   *         key (EDEK).
   */
  public CompletableFuture<EncryptedDocument> encrypt(PlaintextDocument document,
      DocumentMetadata metadata) {
    return this.encryptionService.unwrapKey(document.getEdek(), metadata).thenComposeAsync(
        dek -> encryptFields(document.getDecryptedFields(), metadata, dek, document.getEdek()),
        encryptionExecutor);
  }

  /**
   * Encrypt a map of documents from the ID of the document to the list of fields to encrypt. Makes
   * a call out to the Tenant Security Proxy to generate a collection of new DEK/EDEK pairs for each
   * document ID provided. This function supports partial failure so it returns two Maps, one of
   * document ID to successfully encrypted document and one of document ID to a
   * TenantSecurityException.
   *
   * @param plaintextDocuments Map of document ID to map of fields to encrypt.
   * @param metadata Metadata about all of the documents being encrypted
   * @return Collection of successes and failures that occurred during operation. The keys of each
   *         map returned will be the same keys provided in the original plaintextDocuments map.
   */
  public CompletableFuture<BatchResult<EncryptedDocument>> encryptBatch(
      Map<String, Map<String, byte[]>> plaintextDocuments, DocumentMetadata metadata) {
    return this.encryptionService.batchWrapKeys(plaintextDocuments.keySet(), metadata)
        .thenComposeAsync(batchResponse -> {
          ConcurrentMap<String, WrappedDocumentKey> dekList =
              new ConcurrentHashMap<>(batchResponse.getKeys());
          return CompletableFuture
              .supplyAsync(() -> encryptBatchOfDocuments(plaintextDocuments, metadata, dekList))
              .thenApplyAsync(batchResult -> addTspFailuresToBatchResult(batchResult,
                  batchResponse.getFailures()));
        }, encryptionExecutor);
  }

  /**
   * Re-encrypt a existing map of documents from the ID of the document to the previously encrypted
   * document. Makes a call out to the Tenant Security Proxy to decrypt the EDEKs present in each
   * provided document. This function supports partial failure so it returns two Maps, one of
   * document ID to successfully re-encrypted document and one of document ID to a
   * TenantSecurityException.
   *
   * @param plaintextDocuments Map of previously encrypted document from ID to document.
   * @param metadata Metadata about all of the documents being encrypted
   * @return Collection of successes and failures that occurred during operation. The keys of each
   *         map returned will be the same keys provided in the original plaintextDocuments map.
   */
  public CompletableFuture<BatchResult<EncryptedDocument>> encryptExistingBatch(
      Map<String, PlaintextDocument> plaintextDocuments, DocumentMetadata metadata) {
    // First convert the map from doc ID to plaintext document to a map from doc ID
    // to EDEK to send to batch endpoint
    Map<String, String> edekMap = plaintextDocuments.entrySet().stream()
        .collect(Collectors.toMap(Map.Entry::getKey, eDoc -> eDoc.getValue().getEdek()));
    return this.encryptionService.batchUnwrapKeys(edekMap, metadata)
        .thenComposeAsync(batchResponse -> {
          ConcurrentMap<String, UnwrappedDocumentKey> dekList =
              new ConcurrentHashMap<>(batchResponse.getKeys());
          return CompletableFuture
              .supplyAsync(
                  () -> encryptExistingBatchOfDocuments(plaintextDocuments, metadata, dekList))
              .thenApplyAsync(batchResult -> addTspFailuresToBatchResult(batchResult,
                  batchResponse.getFailures()));
        }, encryptionExecutor);
  }

  /**
   * Decrypt the provided EncryptedDocument. Decrypts the documents encrypted document key (EDEK)
   * using the Tenant Security Proxy and uses it to decrypt and return the document bytes. The DEK
   * is then discarded.
   *
   * @param encryptedDocument Document to decrypt which includes encrypted bytes as well as EDEK.
   * @param metadata Metadata about the document being decrypted.
   * @return PlaintextDocument which contains each documents decrypted field bytes.
   */
  public CompletableFuture<PlaintextDocument> decrypt(EncryptedDocument encryptedDocument,
      DocumentMetadata metadata) {
    return this.encryptionService.unwrapKey(encryptedDocument.getEdek(), metadata).thenComposeAsync(
        decryptedDocumentAESKey -> decryptFields(encryptedDocument.getEncryptedFields(),
            decryptedDocumentAESKey, encryptedDocument.getEdek()));
  }

  /**
   * Re-key a document's encrypted document key (EDEK) using a new KMS config. Decrypts the EDEK
   * then re-encrypts it using the specified tenant's current primary KMS config. The DEK is then
   * discarded.
   *
   * @param edek Encrypted document key to re-key.
   * @param metadata Metadata about the EDEK being re-keyed.
   * @param newTenantId Tenant ID the EDEK should be re-keyed to.
   * @return Newly re-keyed EDEK.
   */
  public CompletableFuture<String> rekeyEdek(String edek, DocumentMetadata metadata,
      String newTenantId) {
    return this.encryptionService.rekey(edek, metadata, newTenantId)
        .thenApply(newKey -> newKey.getEdek());
  }

  /**
   * Decrypt a map of documents from the ID of the document to its encrypted content. Makes a call
   * out to the Tenant Security Proxy to decrypt all of the EDEKs in each document. This function
   * supports partial failure so it returns two Maps, one of document ID to successfully decrypted
   * document and one of document ID to a TenantSecurityException.
   *
   * @param encryptedDocuments Map of documents to decrypt from ID of the document to the
   *        EncryptedDocument
   * @param metadata Metadata to use for each decrypt operation.
   * @return Collection of successes and failures that occurred during operation. The keys of each
   *         map returned will be the same keys provided in the original encryptedDocuments map.
   */
  public CompletableFuture<BatchResult<PlaintextDocument>> decryptBatch(
      Map<String, EncryptedDocument> encryptedDocuments, DocumentMetadata metadata) {
    Map<String, String> edekMap = encryptedDocuments.entrySet().stream()
        .collect(Collectors.toMap(Map.Entry::getKey, eDoc -> eDoc.getValue().getEdek()));
    return this.encryptionService.batchUnwrapKeys(edekMap, metadata)
        .thenComposeAsync(batchResponse -> {
          ConcurrentMap<String, UnwrappedDocumentKey> dekList =
              new ConcurrentHashMap<>(batchResponse.getKeys());
          return CompletableFuture
              .supplyAsync(() -> decryptBatchDocuments(encryptedDocuments, dekList))
              .thenApplyAsync(batchResult -> addTspFailuresToBatchResult(batchResult,
                  batchResponse.getFailures()));
        }, encryptionExecutor);
  }

  /**
   * Send the provided security event to the TSP to be logged and analyzed. Returns Void if the
   * security event was successfully received. Note that logging a security event is an asynchronous
   * operation at the TSP, so successful receipt of a security event does not mean that the event is
   * deliverable or has been delivered to the tenant's logging system. It simply means that the
   * event has been received and will be processed.
   *
   * @param event Security event that represents the action that took place.
   * @param metadata Metadata that provides additional context about the event.
   * @return Void on successful receipt by TSP
   */
  public CompletableFuture<Void> logSecurityEvent(SecurityEvent event, EventMetadata metadata) {
    return this.encryptionService.logSecurityEvent(event, metadata);
  }
}
