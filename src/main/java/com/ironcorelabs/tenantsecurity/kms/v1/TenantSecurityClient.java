package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
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

    /**
     * Default size of web request thread pool. Value value is 25.
     */
    public static int DEFAULT_REQUEST_THREADPOOL_SIZE = 25;

    /**
     * Default size of the threadpool used for AES encryptions/decryptions. Defaults to the number
     * of cores on the machine being run on.
     */
    public static int DEFAULT_AES_THREADPOOL_SIZE = Runtime.getRuntime().availableProcessors();

    /**
     * Constructor for TenantSecurityClient class that uses the SecureRandom
     * NativePRNGNonBlocking instance for random number generation.
     *
     * @param tspDomain Domain where the Tenant Security Proxy is running.
     * @param apiKey    Key to use for requests to the Tenant Security Proxy.
     * @throws Exception If the provided domain is invalid.
     */
    public TenantSecurityClient(String tspDomain, String apiKey) throws Exception {
        this(tspDomain, apiKey, DEFAULT_REQUEST_THREADPOOL_SIZE, DEFAULT_AES_THREADPOOL_SIZE,
                SecureRandom.getInstance("NativePRNGNonBlocking"));
    }

    /**
     * Constructor for TenantSecurityClient class that allows call to provide web request and AES
     * operation thread pool sizes. Uses the SecureRandom NativePRNGNonBlocking instance for random
     * number generation.
     *
     * @param tspDomain         Domain where the Tenant Security Proxy is running.
     * @param apiKey            Key to use for requests to the Tenant Security Proxy.
     * @param requestThreadSize Number of threads to use for fixed-size web request thread pool
     * @param aesThreadSize     Number of threads to use for fixed-size AES operations threadpool
     * @throws Exception If the provided domain is invalid.
     */
    public TenantSecurityClient(String tspDomain, String apiKey, int requestThreadSize,
            int aesThreadSize) throws Exception {
        this(tspDomain, apiKey, requestThreadSize, aesThreadSize,
                SecureRandom.getInstance("NativePRNGNonBlocking"));
    }

    /**
     * Constructor for TenantSecurityClient class that allows call to provide web request and AES
     * operation thread pool sizes. Uses the SecureRandom NativePRNGNonBlocking instance for random
     * number generation.
     *
     * @param tspDomain         Domain where the Tenant Security Proxy is running.
     * @param apiKey            Key to use for requests to the Tenant Security Proxy.
     * @param requestThreadSize Number of threads to use for fixed-size web request thread pool
     * @param aesThreadSize     Number of threads to use for fixed-size AES operations threadpool
     * @param timeout           Request to TSP read and connect timeout in ms.
     *
     * @throws Exception If the provided domain is invalid.
     */
    public TenantSecurityClient(String tspDomain, String apiKey, int requestThreadSize,
            int aesThreadSize, int timeout) throws Exception {
        this(tspDomain, apiKey, requestThreadSize, aesThreadSize,
                SecureRandom.getInstance("NativePRNGNonBlocking"), timeout);
    }

    /**
     * Constructor for TenantSecurityClient class that allows for modifying the random number
     * generator used for encryption. Sets a default connect and read timeout of 20s.
     *
     * @param tspDomain         Domain where the Tenant Security Proxy is running.
     * @param apiKey            Key to use for requests to the Tenant Security Proxy.
     * @param requestThreadSize Number of threads to use for fixed-size web request thread pool
     * @param aesThreadSize     Number of threads to use for fixed-size AES operations threadpool
     * @param randomGen         Instance of SecureRandom to use for PRNG when performing encryption
     *                          operations.
     * @throws Exception If the provided domain is invalid or the provided SecureRandom instance is
     *                   not set.
     */
    public TenantSecurityClient(String tspDomain, String apiKey, int requestThreadSize,
            int aesThreadSize, SecureRandom randomGen) throws Exception {
        this(tspDomain, apiKey, requestThreadSize, aesThreadSize, randomGen, 20000);
    }

    /**
     * Constructor for TenantSecurityClient class that allows for modifying the random number
     * generator used for encryption.
     *
     * @param tspDomain         Domain where the Tenant Security Proxy is running.
     * @param apiKey            Key to use for requests to the Tenant Security Proxy.
     * @param requestThreadSize Number of threads to use for fixed-size web request thread pool
     * @param aesThreadSize     Number of threads to use for fixed-size AES operations threadpool
     * @param randomGen         Instance of SecureRandom to use for PRNG when performing encryption
     *                          operations.
     * @param timeout           Request to TSP read and connect timeout in ms.
     * @throws Exception If the provided domain is invalid or the provided SecureRandom instance is
     *                   not set.
     */
    public TenantSecurityClient(String tspDomain, String apiKey, int requestThreadSize,
            int aesThreadSize, SecureRandom randomGen, int timeout) throws Exception {
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

        this.encryptionExecutor = Executors.newFixedThreadPool(aesThreadSize);

        this.encryptionService =
                new TenantSecurityRequest(tspDomain, apiKey, requestThreadSize, timeout);

        // Update the crypto policy to allow us to use 256 bit AES keys
        Security.setProperty("crypto.policy", "unlimited");
        this.secureRandom = randomGen;
    }

    public void close() throws IOException {
        this.encryptionService.close();
        this.encryptionExecutor.shutdown();
    }

    /**
     * Utility method to create a new client instance which returns a CompletableFuture to help
     * handle error situations which can occur on class construction.
     *
     * @param tspDomain Domain where the Tenant Security Proxy is running.
     * @param apiKey    Key to use for requests to the Tenant Security Proxy.
     * @return CompletableFuture that resolves in a instance of the TenantSecurityClient class.
     */
    public static CompletableFuture<TenantSecurityClient> create(String tspDomain, String apiKey) {
        return CompletableFutures
                .tryCatchNonFatal(() -> new TenantSecurityClient(tspDomain, apiKey));
    }

    /**
     * Encrypt the provided map of fields using the provided encryption key (DEK) and return the
     * resulting encrypted fields in a map from String to encrypted bytes.
     */
    private Map<String, byte[]> encryptFields(Map<String, byte[]> document,DocumentMetadata metadata, byte[] dek) {
        // First, iterate over the map of documents and kick off the encrypt operation
        // Future for each one. As part of doing this, we kick off the operation on to
        // another thread so they run in parallel.
        Map<String, CompletableFuture<byte[]>> encryptOps = document.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> {
                    // Do this mapping in the .collect because we can just map the value. If we
                    // tried doing this in a .map above the .collect we'd have to return another
                    // Entry which is more complicated
                    return CompletableFuture.supplyAsync(
                            () -> CryptoUtils.encryptBytes(entry.getValue(), metadata, dek, this.secureRandom).join(), encryptionExecutor);
               } ));

        // Now iterate over our map of keys to Futures and call join on all of them. We
        // do this in a separate stream() because if we called join() above it'd block
        // each iteration and cause them to be run in CompletableFutures.sequence.
        return encryptOps.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().join()));
    }

    /**
     * Encrypt the provided map of encrypted fields using the provided DEK and return the resulting
     * decrypted fields in a map from String name to decrypted bytes.
     */
    private Map<String, byte[]> decryptFields(Map<String, byte[]> document, byte[] dek) {
        // First map over the encrypted document map and convert the values from
        // encrypted bytes to Futures of decrypted bytes. Make sure each decrypt happens
        // on it's own thread to run them in parallel.
        Map<String, CompletableFuture<byte[]>> decryptOps = document.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> {
                    // Do this mapping in the .collect because we can just map the value. If we
                    // tried doing this in a .map above the .collect we'd have to return another
                    // Entry which is more complicated
                    return CompletableFuture.supplyAsync(() ->CryptoUtils.decryptDocument(entry.getValue(), dek).join(), encryptionExecutor);
                }));
        // Then iterate over the map of Futures and join them to get the decrypted bytes
        // out. Return the map with the same keys passed in, but the values will now be
        // decrypted.
        return decryptOps.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().join()));
    }

    /**
     * Given a map of document IDs to plaintext bytes to encrypt and a map of document IDs to a
     * fresh DEK, iterate over the DEKs and encrypt the document at the same key. It is possible
     * that the DEK list is shorter than the document list in case we had any failures generating
     * new DEKs.
     */
    private ConcurrentMap<String, EncryptedDocument> encryptBatchOfDocuments(
            Map<String, Map<String, byte[]>> documents,
            DocumentMetadata metadata,
            ConcurrentMap<String, WrappedDocumentKey> dekList) {
        return dekList.entrySet().parallelStream()
                .collect(Collectors.toConcurrentMap(ConcurrentMap.Entry::getKey, dekResult -> {
                    String documentId = dekResult.getKey();
                    WrappedDocumentKey documentKeys = dekResult.getValue();
                    Map<String, byte[]> encryptedDoc =
                            encryptFields(documents.get(documentId), metadata, documentKeys.getDekBytes());
                    return new EncryptedDocument(encryptedDoc, documentKeys.getEdek());
                }));
    }

    /**
     * Given a map of document IDs to previously encrypted plaintext documents to re-encrypt and a
     * map of document IDs to the documents DEK, iterate over the DEKs and re-encrypt the document
     * at the same key. It is possible that the DEK list is shorter than the document list in case
     * we had any failures decrypting the existing document DEKs.
     */
    private ConcurrentMap<String, EncryptedDocument> encryptExistingBatchOfDocuments(
            Map<String, PlaintextDocument> documents,
            DocumentMetadata metadata,
            ConcurrentMap<String, UnwrappedDocumentKey> dekList) {
        return dekList.entrySet().parallelStream()
                .collect(Collectors.toConcurrentMap(ConcurrentMap.Entry::getKey, dekResult -> {
                    String documentId = dekResult.getKey();
                    UnwrappedDocumentKey documentKeys = dekResult.getValue();
                    Map<String, byte[]> encryptedDoc =
                            encryptFields(documents.get(documentId).getDecryptedFields(),metadata,
                                    documentKeys.getDekBytes());
                    return new EncryptedDocument(encryptedDoc, documents.get(documentId).getEdek());
                }));
    }

    /**
     * Given a map of document IDs to EncryptedDocument to decrypt and a map of document IDs to a
     * DEK iterate over the DEKs and decrypt the document at the same key. It is possible that the
     * DEK list is shorter than the encrypted document list in case we had any failures unwrapping
     * the provided EDEKs.
     */
    private ConcurrentMap<String, PlaintextDocument> decryptBatchDocuments(
            Map<String, EncryptedDocument> documents,
            ConcurrentMap<String, UnwrappedDocumentKey> dekList) {
        return dekList.entrySet().parallelStream()
                .collect(Collectors.toConcurrentMap(ConcurrentMap.Entry::getKey, dekResult -> {
                    String documentId = dekResult.getKey();
                    UnwrappedDocumentKey documentKeys = dekResult.getValue();
                    EncryptedDocument eDoc = documents.get(documentId);
                    Map<String, byte[]> decryptedDoc =
                            decryptFields(eDoc.getEncryptedFields(), documentKeys.getDekBytes());
                    return new PlaintextDocument(decryptedDoc, eDoc.getEdek());
                }));
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
     * Encrypt the bytes in input and write it to output. A new key will be wrapped
     * using the TSP. The returned value contains the edek needed to decrypt the
     * resulting stream.
     * 
     * @param input    The input stream of bytes to encrypt.
     * @param output   The output stream to write encrypted bytes to.
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
     * Decrypt the bytes that are represented by input using the key contained
     * inside the edek. Unverified bytes will be written to the output stream. Once
     * the GCM tag has been reached and verified, this function will return. If
     * there is a problem with the document represented by input or a problem
     * unwrapping the edek the returned CompletableFuture will return an exception
     * instead. If an exception is thrown the contents of the output stream should
     * not be used at all.
     * 
     * @param edek     The encrypted dek which should be unwrapped by the TSP.
     * @param input    A stream representing the encrypted document.
     * @param output   An output stream to write the decrypted document to. Note
     *                 that this output should not be used until after the future
     *                 exits successfully because the GCM tag is not fully verified
     *                 until that time.
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
     * @param document Document to encrypt. Each field in the provided document will be encrypted
     *                 with the same key.
     * @param metadata Metadata about the document being encrypted.
     * @return Encrypted document and base64 encrypted document key (EDEK) wrapped in a
     *         EncryptedResult class.
     */
    public CompletableFuture<EncryptedDocument> encrypt(Map<String, byte[]> document,
            DocumentMetadata metadata) {
        return this.encryptionService.wrapKey(metadata).thenApplyAsync(newDocumentKeys -> {
            return new EncryptedDocument(encryptFields(document, metadata, newDocumentKeys.getDekBytes()),
                    newDocumentKeys.getEdek());
        });
    }

    /**
     * Encrypt the provided document reusing an existing encrypted document encryption key (EDEK).
     * Makes a call out to the Tenant Security Proxy to decrypt the EDEK and then uses the resulting
     * key (DEK) to encrypt the document. This allows callers to update/re-encrypt data that has
     * already been encrypted with an existing key. For example, if multiple columns in a DB row are
     * all encrypted to the same key and one of those columns needs to be updated, this method
     * allows the caller to update a single column without having to re-encrypt every field in the
     * row with a new key.
     *
     * @param document PlaintextDocument which contains the encrypted document key (EDEK) as well as
     *                 the Map of bytes to encrypt.
     * @param metadata Metadata about the document being encrypted.
     * @return EncryptedDocument which contains a map of encrypted bytes and base64 encrypted
     *         document key (EDEK).
     */
    public CompletableFuture<EncryptedDocument> encrypt(PlaintextDocument document,
            DocumentMetadata metadata) {
        return this.encryptionService.unwrapKey(document.getEdek(), metadata)
                .thenApplyAsync(dek -> new EncryptedDocument(
                        encryptFields(document.getDecryptedFields(), metadata, dek), document.getEdek()),
                        encryptionExecutor);
    }

    /**
     * Encrypt a map of documents from the ID of the document to the list of fields to encrypt.
     * Makes a call out to the Tenant Security Proxy to generate a collection of new DEK/EDEK pairs
     * for each document ID provided. This function supports partial failure so it returns two Maps,
     * one of document ID to successfully encrypted document and one of document ID to a
     * TenantSecurityException.
     *
     * @param plaintextDocuments Map of document ID to map of fields to encrypt.
     * @param metadata           Metadata about all of the documents being encrypted
     * @return Collection of successes and failures that occurred during operation. The keys of each
     *         map returned will be the same keys provided in the original plaintextDocuments map.
     */
    public CompletableFuture<BatchResult<EncryptedDocument>> encryptBatch(
            Map<String, Map<String, byte[]>> plaintextDocuments, DocumentMetadata metadata) {
        return this.encryptionService.batchWrapKeys(plaintextDocuments.keySet(), metadata)
                .thenComposeAsync(batchResponse -> {
                    ConcurrentMap<String, WrappedDocumentKey> dekList =
                            new ConcurrentHashMap<>(batchResponse.getKeys());
                    ConcurrentMap<String, ErrorResponse> failureList =
                            new ConcurrentHashMap<>(batchResponse.getFailures());
                    return CompletableFuture
                            .supplyAsync(() -> encryptBatchOfDocuments(plaintextDocuments, metadata, dekList))
                            .thenCombine(
                                    CompletableFuture
                                            .supplyAsync(() -> getBatchFailures(failureList)),
                                    (s, f) -> new BatchResult<EncryptedDocument>(s, f));
                }, encryptionExecutor);
    }

    /**
     * Re-encrypt a existing map of documents from the ID of the document to the previously
     * encrypted document. Makes a call out to the Tenant Security Proxy to decrypt the EDEKs
     * present in each provided document. This function supports partial failure so it returns two
     * Maps, one of document ID to successfully re-encrypted document and one of document ID to a
     * TenantSecurityException.
     *
     * @param plaintextDocuments Map of previously encrypted document from ID to document.
     * @param metadata           Metadata about all of the documents being encrypted
     * @return Collection of successes and failures that occurred during operation. The keys of each
     *         map returned will be the same keys provided in the original plaintextDocuments map.
     */
    public CompletableFuture<BatchResult<EncryptedDocument>> encryptExistingBatch(
            Map<String, PlaintextDocument> plaintextDocuments, DocumentMetadata metadata) {
        // First convert the map from doc ID to plaintext document to a map from doc ID
        // to EDEK to send to batch endpoint
        Map<String, String> edekMap = plaintextDocuments.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, (eDoc) -> eDoc.getValue().getEdek()));
        return this.encryptionService.batchUnwrapKeys(edekMap, metadata)
                .thenComposeAsync(batchResponse -> {
                    ConcurrentMap<String, UnwrappedDocumentKey> dekList =
                            new ConcurrentHashMap<>(batchResponse.getKeys());
                    ConcurrentMap<String, ErrorResponse> failureList =
                            new ConcurrentHashMap<>(batchResponse.getFailures());
                    return CompletableFuture.supplyAsync(
                            () -> encryptExistingBatchOfDocuments(plaintextDocuments, metadata, dekList))
                            .thenCombine(
                                    CompletableFuture
                                            .supplyAsync(() -> getBatchFailures(failureList)),
                                    (s, f) -> new BatchResult<EncryptedDocument>(s, f));
                }, encryptionExecutor);
    }

    /**
     * Decrypt the provided EncryptedDocument. Decrypts the documents encrypted document key (EDEK)
     * using the Tenant Security Proxy and uses it to decrypt and return the document bytes. The DEK
     * is then discarded.
     *
     * @param encryptedDocument Document to decrypt which includes encrypted bytes as well as EDEK.
     * @param metadata          Metadata about the document being decrypted.
     * @return PlaintextDocument which contains each documents decrypted field bytes.
     */
    public CompletableFuture<PlaintextDocument> decrypt(EncryptedDocument encryptedDocument,
            DocumentMetadata metadata) {
        return this.encryptionService.unwrapKey(encryptedDocument.getEdek(), metadata)
                .thenApplyAsync(decryptedDocumentAESKey -> {
                    Map<String, byte[]> decryptedFields = decryptFields(
                            encryptedDocument.getEncryptedFields(), decryptedDocumentAESKey);
                    return new PlaintextDocument(decryptedFields, encryptedDocument.getEdek());
                });
    }

        /**
         * Re-key an EncryptedDocument to a new tenant without decrypting the document data. Decrypts the
         * document's encrypted document key (EDEK) then re-encrypts it to the new tenant. The DEK is then discarded.
         * The old tenant and new tenant can be the same in order to re-key the document to the tenant's latest primary config.
         *
         * @param encryptedDocument Document to re-key which includes encrypted bytes as well as EDEK.
         * @param metadata          Metadata about the document being re-keyed.
         * @param newTenantId       Tenant ID the document should be re-keyed to.
         * @return                  EncryptedDocument that contains the new EDEK and unaltered encrypted fields.
         */
        public CompletableFuture<EncryptedDocument> rekeyDocument(EncryptedDocument encryptedDocument,
                        DocumentMetadata metadata, String newTenantId) {
                return this.encryptionService.rekey(encryptedDocument.getEdek(), metadata, newTenantId)
                                .thenApply(newKey -> new EncryptedDocument(encryptedDocument.getEncryptedFields(),
                                                newKey.getEdek()));
        }

    /**
     * Decrypt a map of documents from the ID of the document to its encrypted content. Makes a call
     * out to the Tenant Security Proxy to decrypt all of the EDEKs in each document. This function
     * supports partial failure so it returns two Maps, one of document ID to successfully decrypted
     * document and one of document ID to a TenantSecurityException.
     *
     * @param encryptedDocuments Map of documents to decrypt from ID of the document to the
     *                           EncryptedDocument
     * @param metadata           Metadata to use for each decrypt operation.
     * @return Collection of successes and failures that occurred during operation. The keys of each
     *         map returned will be the same keys provided in the original encryptedDocuments map.
     */
    public CompletableFuture<BatchResult<PlaintextDocument>> decryptBatch(
            Map<String, EncryptedDocument> encryptedDocuments, DocumentMetadata metadata) {
        Map<String, String> edekMap = encryptedDocuments.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, (eDoc) -> eDoc.getValue().getEdek()));
        return this.encryptionService.batchUnwrapKeys(edekMap, metadata)
                .thenComposeAsync(batchResponse -> {
                    ConcurrentMap<String, UnwrappedDocumentKey> dekList =
                            new ConcurrentHashMap<>(batchResponse.getKeys());
                    ConcurrentMap<String, ErrorResponse> failureList =
                            new ConcurrentHashMap<>(batchResponse.getFailures());
                    return CompletableFuture
                            .supplyAsync(() -> decryptBatchDocuments(encryptedDocuments, dekList))
                            .thenCombine(
                                    CompletableFuture
                                            .supplyAsync(() -> getBatchFailures(failureList)),
                                    (s, f) -> new BatchResult<PlaintextDocument>(s, f));
                }, encryptionExecutor);
    }

    /**
     * Send the provided security event to the TSP to be logged and analyzed. Returns Void if the
     * security event was successfully received. Note that logging a security event is an
     * asynchronous operation at the TSP, so successful receipt of a security event does not mean
     * that the event is deliverable or has been delivered to the tenant's logging system. It simply
     * means that the event has been received and will be processed.
     *
     * @param event    Security event that represents the action that took place.
     * @param metadata Metadata that provides additional context about the event.
     * @return Void on successful receipt by TSP
     */
    public CompletableFuture<Void> logSecurityEvent(SecurityEvent event, EventMetadata metadata) {
        return this.encryptionService.logSecurityEvent(event, metadata);
    }
}
