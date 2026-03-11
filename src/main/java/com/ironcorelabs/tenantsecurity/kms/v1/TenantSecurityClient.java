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
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.logdriver.v1.EventMetadata;
import com.ironcorelabs.tenantsecurity.logdriver.v1.SecurityEvent;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

/**
 * TenantSecurityClient class that can be used to encrypt and decrypt documents.
 *
 * @author IronCore Labs
 */
public final class TenantSecurityClient implements Closeable, DocumentDecryptor, DocumentEncryptor {
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
   * @param allowInsecureHttp If normal http should be allowed.
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
     * Construct the TenantSecurityClient from the builder.
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
              return DocumentCryptoOps.encryptFields(documents.get(documentId), metadata,
                  documentKeys.getDekBytes(), documentKeys.getEdek(), encryptionExecutor,
                  secureRandom);
            }));
    return DocumentCryptoOps.cryptoOperationToBatchResult(encryptResults,
        TenantSecurityErrorCodes.DOCUMENT_ENCRYPT_FAILED);
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
              return DocumentCryptoOps.encryptFields(documents.get(documentId).getDecryptedFields(),
                  metadata, documentKeys.getDekBytes(), documents.get(documentId).getEdek(),
                  encryptionExecutor, secureRandom);
            }));
    return DocumentCryptoOps.cryptoOperationToBatchResult(encryptResults,
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
              return DocumentCryptoOps.decryptFields(eDoc.getEncryptedFields(),
                  documentKeys.getDekBytes(), eDoc.getEdek(), encryptionExecutor);
            }));
    return DocumentCryptoOps.cryptoOperationToBatchResult(decryptResults,
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
  @Override
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
  @Override
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
  @Override
  public CompletableFuture<EncryptedDocument> encrypt(Map<String, byte[]> document,
      DocumentMetadata metadata) {
    return this.encryptionService.wrapKey(metadata)
        .thenComposeAsync(newDocumentKeys -> DocumentCryptoOps.encryptFields(document, metadata,
            newDocumentKeys.getDekBytes(), newDocumentKeys.getEdek(), encryptionExecutor,
            secureRandom));
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
    return this.encryptionService.unwrapKey(document.getEdek(), metadata)
        .thenComposeAsync(dek -> DocumentCryptoOps.encryptFields(document.getDecryptedFields(),
            metadata, dek, document.getEdek(), encryptionExecutor, secureRandom),
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
  @Override
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
  @Override
  public CompletableFuture<PlaintextDocument> decrypt(EncryptedDocument encryptedDocument,
      DocumentMetadata metadata) {
    return this.encryptionService.unwrapKey(encryptedDocument.getEdek(), metadata)
        .thenComposeAsync(decryptedDocumentAESKey -> DocumentCryptoOps.decryptFields(
            encryptedDocument.getEncryptedFields(), decryptedDocumentAESKey,
            encryptedDocument.getEdek(), encryptionExecutor));
  }

  // === Private helpers for creating CachedKey instances ===

  private CompletableFuture<CachedKey> newCachedKeyFromUnwrap(String edek,
      DocumentMetadata metadata) {
    return this.encryptionService.unwrapKey(edek, metadata).thenApply(dekBytes -> {
      CachedKey cachedKey = new CachedKey(dekBytes, edek, this.encryptionExecutor,
          this.secureRandom, this.encryptionService, metadata);
      Arrays.fill(dekBytes, (byte) 0);
      return cachedKey;
    });
  }

  private CompletableFuture<CachedKey> newCachedKeyFromWrap(DocumentMetadata metadata) {
    return this.encryptionService.wrapKey(metadata).thenApply(wrappedKey -> {
      byte[] dekBytes = wrappedKey.getDekBytes();
      CachedKey cachedKey = new CachedKey(dekBytes, wrappedKey.getEdek(), this.encryptionExecutor,
          this.secureRandom, this.encryptionService, metadata);
      Arrays.fill(dekBytes, (byte) 0);
      return cachedKey;
    });
  }

  /**
   * Execute an operation on a cached resource with automatic lifecycle management. The resource is
   * closed (and DEK zeroed) when the operation completes, whether successfully or with an error.
   */
  private <K extends CachedKeyLifecycle, T> CompletableFuture<T> withCachedResource(
      CompletableFuture<K> resource, Function<K, CompletableFuture<T>> operation) {
    return resource.thenCompose(k -> operation.apply(k).whenComplete((result, error) -> k.close()));
  }

  // === Cached decryptor factory methods ===

  /**
   * Create a CachedDecryptor for repeated decrypt operations using the same DEK. This unwraps the
   * EDEK once and caches the resulting DEK for subsequent decrypts.
   *
   * <p>
   * Use this when you need to decrypt multiple documents that share the same EDEK, to avoid
   * repeated TSP unwrap calls.
   *
   * <p>
   * The returned CachedDecryptor implements Closeable and should be used with try-with-resources to
   * ensure the DEK is securely zeroed when done:
   *
   * <pre>
   * try (CachedDecryptor decryptor = client.createCachedDecryptor(edek, metadata).get()) {
   *   PlaintextDocument doc1 = decryptor.decrypt(encDoc1, metadata).get();
   *   PlaintextDocument doc2 = decryptor.decrypt(encDoc2, metadata).get();
   * }
   * </pre>
   *
   * @param edek The encrypted document encryption key to unwrap
   * @param metadata Metadata for the unwrap operation
   * @return CompletableFuture resolving to a CachedDecryptor
   */
  public CompletableFuture<CachedDecryptor> createCachedDecryptor(String edek,
      DocumentMetadata metadata) {
    return newCachedKeyFromUnwrap(edek, metadata).thenApply(k -> k);
  }

  /**
   * Create a CachedDecryptor from an existing EncryptedDocument. Convenience method that extracts
   * the EDEK from the document.
   *
   * @param encryptedDocument The encrypted document whose EDEK should be unwrapped
   * @param metadata Metadata for the unwrap operation
   * @return CompletableFuture resolving to a CachedDecryptor
   */
  public CompletableFuture<CachedDecryptor> createCachedDecryptor(
      EncryptedDocument encryptedDocument, DocumentMetadata metadata) {
    return createCachedDecryptor(encryptedDocument.getEdek(), metadata);
  }

  /**
   * Execute an operation using a CachedDecryptor with automatic lifecycle management. The cached
   * key is automatically closed (and DEK zeroed) when the operation completes, whether successfully
   * or with an error.
   *
   * <p>
   * This is the recommended pattern for using cached decryptors with CompletableFuture composition:
   *
   * <pre>
   * client.withCachedDecryptor(edek, metadata, decryptor -&gt; decryptor.decrypt(encDoc1, metadata)
   *     .thenCompose(doc1 -&gt; decryptor.decrypt(encDoc2, metadata)))
   * </pre>
   *
   * @param <T> The type returned by the operation
   * @param edek The encrypted document encryption key to unwrap
   * @param metadata Metadata for the unwrap operation
   * @param operation Function that takes the CachedDecryptor and returns a CompletableFuture
   * @return CompletableFuture resolving to the operation's result
   */
  public <T> CompletableFuture<T> withCachedDecryptor(String edek, DocumentMetadata metadata,
      Function<CachedDecryptor, CompletableFuture<T>> operation) {
    return withCachedResource(createCachedDecryptor(edek, metadata), operation);
  }

  /**
   * Execute an operation using a CachedDecryptor with automatic lifecycle management. Convenience
   * method that extracts the EDEK from the document.
   *
   * @param <T> The type returned by the operation
   * @param encryptedDocument The encrypted document whose EDEK should be unwrapped
   * @param metadata Metadata for the unwrap operation
   * @param operation Function that takes the CachedDecryptor and returns a CompletableFuture
   * @return CompletableFuture resolving to the operation's result
   */
  public <T> CompletableFuture<T> withCachedDecryptor(EncryptedDocument encryptedDocument,
      DocumentMetadata metadata, Function<CachedDecryptor, CompletableFuture<T>> operation) {
    return withCachedDecryptor(encryptedDocument.getEdek(), metadata, operation);
  }

  // === Cached encryptor factory methods ===

  /**
   * Create a CachedEncryptor for repeated encrypt operations using the same DEK. This wraps a new
   * key once and caches the resulting DEK/EDEK pair for subsequent encrypts. All documents
   * encrypted with this instance will share the same DEK/EDEK pair.
   *
   * <p>
   * Use this when you need to encrypt multiple documents for the same tenant in quick succession,
   * to avoid repeated TSP wrap calls.
   *
   * <p>
   * The returned CachedEncryptor implements Closeable and should be used with try-with-resources to
   * ensure the DEK is securely zeroed when done:
   *
   * <pre>
   * try (CachedEncryptor encryptor = client.createCachedEncryptor(metadata).get()) {
   *   EncryptedDocument enc1 = encryptor.encrypt(doc1, metadata).get();
   *   EncryptedDocument enc2 = encryptor.encrypt(doc2, metadata).get();
   * }
   * </pre>
   *
   * @param metadata Metadata for the wrap operation
   * @return CompletableFuture resolving to a CachedEncryptor
   */
  public CompletableFuture<CachedEncryptor> createCachedEncryptor(DocumentMetadata metadata) {
    return newCachedKeyFromWrap(metadata).thenApply(k -> k);
  }

  /**
   * Execute an operation using a CachedEncryptor with automatic lifecycle management. The cached
   * key is automatically closed (and DEK zeroed) when the operation completes, whether successfully
   * or with an error.
   *
   * <p>
   * This is the recommended pattern for using cached encryptors with CompletableFuture composition:
   *
   * <pre>
   * client.withCachedEncryptor(metadata, encryptor -&gt; encryptor.encrypt(doc1, metadata)
   *     .thenCompose(enc1 -&gt; encryptor.encrypt(doc2, metadata)))
   * </pre>
   *
   * @param <T> The type returned by the operation
   * @param metadata Metadata for the wrap operation
   * @param operation Function that takes the CachedEncryptor and returns a CompletableFuture
   * @return CompletableFuture resolving to the operation's result
   */
  public <T> CompletableFuture<T> withCachedEncryptor(DocumentMetadata metadata,
      Function<CachedEncryptor, CompletableFuture<T>> operation) {
    return withCachedResource(createCachedEncryptor(metadata), operation);
  }

  // === CachedKey factory methods (full encrypt + decrypt access) ===

  /**
   * Create a CachedKey for both encrypt and decrypt operations. Wraps a new key and caches the
   * resulting DEK/EDEK pair.
   *
   * <p>
   * Use this when you need both encrypt and decrypt capabilities with the same cached key. If you
   * only need encrypt or decrypt, prefer {@link #createCachedEncryptor(DocumentMetadata)} or
   * {@link #createCachedDecryptor(String, DocumentMetadata)} for narrower type safety.
   *
   * @param metadata Metadata for the wrap operation
   * @return CompletableFuture resolving to a CachedKey
   */
  public CompletableFuture<CachedKey> createCachedKey(DocumentMetadata metadata) {
    return newCachedKeyFromWrap(metadata);
  }

  /**
   * Create a CachedKey for both encrypt and decrypt operations by unwrapping an existing EDEK.
   *
   * @param edek The encrypted document encryption key to unwrap
   * @param metadata Metadata for the unwrap operation
   * @return CompletableFuture resolving to a CachedKey
   */
  public CompletableFuture<CachedKey> createCachedKey(String edek, DocumentMetadata metadata) {
    return newCachedKeyFromUnwrap(edek, metadata);
  }

  /**
   * Create a CachedKey for both encrypt and decrypt operations from an existing EncryptedDocument.
   * Convenience method that extracts the EDEK from the document.
   *
   * @param encryptedDocument The encrypted document whose EDEK should be unwrapped
   * @param metadata Metadata for the unwrap operation
   * @return CompletableFuture resolving to a CachedKey
   */
  public CompletableFuture<CachedKey> createCachedKey(EncryptedDocument encryptedDocument,
      DocumentMetadata metadata) {
    return createCachedKey(encryptedDocument.getEdek(), metadata);
  }

  /**
   * Execute an operation using a CachedKey with automatic lifecycle management. Wraps a new key and
   * provides full encrypt + decrypt access.
   *
   * @param <T> The type returned by the operation
   * @param metadata Metadata for the wrap operation
   * @param operation Function that takes the CachedKey and returns a CompletableFuture
   * @return CompletableFuture resolving to the operation's result
   */
  public <T> CompletableFuture<T> withCachedKey(DocumentMetadata metadata,
      Function<CachedKey, CompletableFuture<T>> operation) {
    return withCachedResource(createCachedKey(metadata), operation);
  }

  /**
   * Execute an operation using a CachedKey with automatic lifecycle management. Unwraps an existing
   * EDEK and provides full encrypt + decrypt access.
   *
   * @param <T> The type returned by the operation
   * @param edek The encrypted document encryption key to unwrap
   * @param metadata Metadata for the unwrap operation
   * @param operation Function that takes the CachedKey and returns a CompletableFuture
   * @return CompletableFuture resolving to the operation's result
   */
  public <T> CompletableFuture<T> withCachedKey(String edek, DocumentMetadata metadata,
      Function<CachedKey, CompletableFuture<T>> operation) {
    return withCachedResource(createCachedKey(edek, metadata), operation);
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
  @Override
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
