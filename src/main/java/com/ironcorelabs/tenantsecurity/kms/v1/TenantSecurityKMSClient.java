package com.ironcorelabs.tenantsecurity.kms.v1;

import java.net.URL;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

/**
 * TenantSecurityKMSClient class that can be used to encrypt and decrypt
 * documents.
 *
 * @author IronCore Labs
 */
public final class TenantSecurityKMSClient {
    private static final String AES_ALGO = "AES/GCM/NoPadding";
    private static final int IV_BYTE_LENGTH = 12;
    private static final int GCM_TAG_BIT_LENGTH = 128;
    // the size of the fixed length portion of the header (version, magic, size)
    private static final int DOCUMENT_HEADER_META_LENGTH = 7;
    private static final byte CURRENT_DOCUMENT_HEADER_VERSION = 3;
    private static final byte[] DOCUMENT_MAGIC = { 73, 82, 79, 78 }; // bytes for ASCII IRON characters
    private final SecureRandom secureRandom;

    // Use fixed size thread pool for CPU bound operations (crypto ops). Defaults to
    // CPU-cores but configurable on construction.
    private ExecutorService encryptionExecutor;

    private TenantSecurityKMSRequest encryptionService;

    /**
     * Default size of web request thread pool. Value value is 25.
     */
    public static int DEFAULT_REQUEST_THREADPOOL_SIZE = 25;

    /**
     * Default size of the threadpool used for AES encryptions/decryptions. Defaults
     * to the number of cores on the machine being run on.
     */
    public static int DEFAULT_AES_THREADPOOL_SIZE = Runtime.getRuntime().availableProcessors();

    /**
     * Constructor for TenantSecurityKMSClient class that allows for modifying the
     * random number generator used for encryption.
     *
     * @param tspDomain         Domain where the Tenant Security Proxy is running.
     * @param apiKey            Key to use for requests to the Tenant Security
     *                          Proxy.
     * @param requestThreadSize Number of threads to use for fixed-size web request
     *                          thread pool
     * @param aesThreadSize     Number of threads to use for fixed-size AES
     *                          operations threadpool
     * @param randomGen         Instance of SecureRandom to use for PRNG when
     *                          performing encryption operations.
     * @throws Exception If the provided domain is invalid or the provided
     *                   SecureRandom instance is not set.
     */
    public TenantSecurityKMSClient(String tspDomain, String apiKey, int requestThreadSize, int aesThreadSize,
            SecureRandom randomGen) throws Exception {
        // Use the URL class to validate the form of the provided TSP domain URL
        new URL(tspDomain);
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalArgumentException("No value provided for apiKey!");
        }
        if (randomGen == null) {
            throw new IllegalArgumentException("No value provided for random number generator!");
        }
        if (requestThreadSize < 1) {
            throw new IllegalArgumentException("Value provided for request threadpool size must be greater than 0!");
        }
        if (aesThreadSize < 1) {
            throw new IllegalArgumentException("Value provided for AES threadpool size must be greater than 0!");
        }

        this.encryptionExecutor = Executors.newFixedThreadPool(aesThreadSize);

        this.encryptionService = new TenantSecurityKMSRequest(tspDomain, apiKey, requestThreadSize);

        // Update the crypto policy to allow us to use 256 bit AES keys
        Security.setProperty("crypto.policy", "unlimited");
        this.secureRandom = randomGen;
    }

    /**
     * Constructor for TenantSecurityKMSClient class that allows call to provide web
     * request and AES operation thread pool sizes. Uses the SecureRandom
     * NativePRNGNonBlocking instance for random number generation.
     *
     * @param tspDomain         Domain where the Tenant Security Proxy is running.
     * @param apiKey            Key to use for requests to the Tenant Security
     *                          Proxy.
     * @param requestThreadSize Number of threads to use for fixed-size web request
     *                          thread pool
     * @param aesThreadSize     Number of threads to use for fixed-size AES
     *                          operations threadpool
     * @throws Exception If the provided domain is invalid.
     */
    public TenantSecurityKMSClient(String tspDomain, String apiKey, int requestThreadSize, int aesThreadSize)
            throws Exception {
        this(tspDomain, apiKey, requestThreadSize, aesThreadSize, SecureRandom.getInstance("NativePRNGNonBlocking"));
    }

    /**
     * Constructor for TenantSecurityKMSClient class that uses the SecureRandom
     * NativePRNGNonBlocking instance for random number generation.
     *
     * @param tspDomain Domain where the Tenant Security Proxy is running.
     * @param apiKey    Key to use for requests to the Tenant Security Proxy.
     * @throws Exception If the provided domain is invalid.
     */
    public TenantSecurityKMSClient(String tspDomain, String apiKey) throws Exception {
        this(tspDomain, apiKey, DEFAULT_REQUEST_THREADPOOL_SIZE, DEFAULT_AES_THREADPOOL_SIZE,
                SecureRandom.getInstance("NativePRNGNonBlocking"));
    }

    /**
     * Utility method to create a new client instance which returns a
     * CompletableFuture to help handle error situations which can occur on class
     * construction.
     *
     * @param tspDomain Domain where the Tenant Security Proxy is running.
     * @param apiKey    Key to use for requests to the Tenant Security Proxy.
     * @return CompletableFuture that resolves in a instance of the
     *         TenantSecurityKMSClient class.
     */
    public static CompletableFuture<TenantSecurityKMSClient> create(String tspDomain, String apiKey) {
        return CompletableFutures.tryCatchNonFatal(() -> new TenantSecurityKMSClient(tspDomain, apiKey));
    }

    /**
     * Generate a header to mark the encrypted document as ours. Right now this is
     * all constant; in the future this will contain a protobuf bytes header of
     * variable length.
     */
    private static byte[] generateHeader() {
        final byte headerVersion = CURRENT_DOCUMENT_HEADER_VERSION;
        final byte[] magic = DOCUMENT_MAGIC;
        final byte[] headerSize = { (byte) 0, (byte) 0 };
        return ByteBuffer.allocate(DOCUMENT_HEADER_META_LENGTH).put(headerVersion).put(magic).put(headerSize).array();
    }

    /**
     * Given the provided document bytes and an AES key, encrypt and return the
     * encrypted bytes.
     */
    private CompletableFuture<byte[]> encryptBytes(byte[] document, byte[] documentKey) {
        byte[] iv = new byte[IV_BYTE_LENGTH];
        secureRandom.nextBytes(iv);

        return CompletableFutures.tryCatchNonFatal(() -> {
            final Cipher cipher = Cipher.getInstance(AES_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(documentKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv));
            byte[] encryptedBytes = cipher.doFinal(document);
            byte[] header = generateHeader();

            // Store the IV at the front of the resulting encrypted data
            return ByteBuffer.allocate(header.length + IV_BYTE_LENGTH + encryptedBytes.length).put(header).put(iv)
                    .put(encryptedBytes).array();
        });
    }

    /**
     * Check that the given bytes contain 4 bytes of ASCII representing "IRON"
     * document magic. This magic should start at index 1, after the expected header
     * version byte.
     */
    private static boolean containsIroncoreMagic(byte[] bytes) {
        return bytes.length >= 5 && ByteBuffer.wrap(bytes, 1, 4).compareTo(ByteBuffer.wrap(DOCUMENT_MAGIC)) == 0;
    }

    /**
     * Multiply the header size bytes at the 5th and 6th indices to get the header
     * size. If those bytes don't exist this will throw.
     */
    private static int getHeaderSize(byte[] bytes) {
        return bytes[5] * 256 + bytes[6];
    }

    /**
     * Check if an IronCore header is present in some bytes, indicating that it is
     * ciphertext.
     *
     * @param bytes bytes to be checked
     */
    public static boolean isCiphertext(byte[] bytes) {
        // Header size is currently always 0 for CMK encrypted docs. Expect at least one
        // byte following the header that would have been encrypted.
        // whenever header size is not 0, this should include a check that
        // bytes.length > META_LENGTH + headerSize
        return bytes.length > DOCUMENT_HEADER_META_LENGTH && bytes[0] == CURRENT_DOCUMENT_HEADER_VERSION
                && containsIroncoreMagic(bytes) && getHeaderSize(bytes) == 0;
    }

    /**
     * Parses the header off the encrypted document and returns a ByteBuffer
     * wrapping the document bytes. Once the header contains metadata we care about,
     * this will return a class containing the document bytes and the header.
     */
    private static CompletableFuture<ByteBuffer> parseDocumentParts(byte[] document) {
        return CompletableFutures.tryCatchNonFatal(() -> {
            if (!isCiphertext(document)) {
                throw new IllegalArgumentException("Provided bytes were not an Ironcore encrypted document.");
            }
            int totalHeaderSize = getHeaderSize(document) + DOCUMENT_HEADER_META_LENGTH;
            int newLength = document.length - totalHeaderSize;
            return ByteBuffer.wrap(document, totalHeaderSize, newLength);
        });
    }

    /**
     * Given the provided encrypted document (which has an IV prepended to it) and
     * an AES key, decrypt and return the decrypted bytes.
     */
    private CompletableFuture<byte[]> decryptBytes(ByteBuffer encryptedDocument, byte[] documentKey) {
        byte[] iv = new byte[IV_BYTE_LENGTH];

        // Pull out the IV from the front of the encrypted data
        encryptedDocument.get(iv);
        byte[] encryptedBytes = new byte[encryptedDocument.remaining()];
        encryptedDocument.get(encryptedBytes);

        return CompletableFutures.tryCatchNonFatal(() -> {
            final Cipher cipher = Cipher.getInstance(AES_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(documentKey, "AES"),
                    new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv));
            return cipher.doFinal(encryptedBytes);
        });
    }

    /**
     * Encrypt the provided map of fields using the provided encryption key (DEK)
     * and return the resulting encrypted fields in a map from String to encrypted
     * bytes.
     */
    private Map<String, byte[]> encryptFields(Map<String, byte[]> document, DocumentMetadata metadata, byte[] dek) {
        // First, iterate over the map of documents and kick off the encrypt operation
        // Future for each one. As part of doing this, we kick off the operation on to
        // another thread so they run in parallel.
        Map<String, CompletableFuture<byte[]>> encryptOps = document.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> {
                    // Do this mapping in the .collect because we can just map the value. If we
                    // tried doing this in a .map above the .collect we'd have to return another
                    // Entry which is more complicated
                    return CompletableFuture.supplyAsync(() -> encryptBytes(entry.getValue(), dek).join(),
                            encryptionExecutor);
                }));

        // Now iterate over our map of keys to Futures and call join on all of them. We
        // do this in a separate stream() because if we called join() above it'd block
        // each iteration and cause them to be run in CompletableFutures.sequence.
        Map<String, byte[]> encryptedMap = encryptOps.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().join()));
        return encryptedMap;
    }

    /**
     * Encrypt the provided map of encrypted fields using the provided DEK and
     * return the resulting decrypted fields in a map from String name to decrypted
     * bytes.
     */
    private Map<String, byte[]> decryptFields(Map<String, byte[]> document, DocumentMetadata metadata, byte[] dek) {
        // First map over the encrypted document map and convert the values from
        // encrypted bytes to Futures of decrypted bytes. Make sure each decrypt happens
        // on it's own thread to run them in parallel.
        Map<String, CompletableFuture<byte[]>> decryptOps = document.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> {
                    // Do this mapping in the .collect because we can just map the value. If we
                    // tried doing this in a .map above the .collect we'd have to return another
                    // Entry which is more complicated
                    return CompletableFuture.supplyAsync(
                            () -> parseDocumentParts(entry.getValue())
                                    .thenCompose(encryptedDocument -> decryptBytes(encryptedDocument, dek)).join(),
                            encryptionExecutor);
                }));
        // Then iterate over the map of Futures and join them to get the decrypted bytes
        // out. Return the map with the same keys passed in, but the values will now be
        // decrypted.
        Map<String, byte[]> decryptedDocument = decryptOps.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, entry -> entry.getValue().join()));
        return decryptedDocument;
    }

    /**
     * Encrypt the provided document. Documents are provided as a map of fields from
     * the document id/name (String) to bytes (byte[]). Uses the Tenant Security
     * Proxy to generate a new document encryption key (DEK), encrypt that key
     * (EDEK) and then uses the DEK to encrypt all of the provided document fields.
     * Returns an EncryptedDocument which contains a Map from each fields id/name to
     * encrypted bytes as well as the EDEK and discards the DEK.
     *
     * @param document Document to encrypt. Each field in the provided document will
     *                 be encrypted with the same key.
     * @param metadata Metadata about the document being encrypted.
     * @return Encrypted document and base64 encrypted document key (EDEK) wrapped
     *         in a EncryptedResult class.
     */
    public CompletableFuture<EncryptedDocument> encrypt(Map<String, byte[]> document, DocumentMetadata metadata) {
        return this.encryptionService.wrapKey(metadata).thenApplyAsync(newDocumentKeys -> {
            return new EncryptedDocument(encryptFields(document, metadata, newDocumentKeys.getDekBytes()),
                    newDocumentKeys.getEdek());
        });
    }

    /**
     * Encrypt the provided document reusing an existing encrypted document
     * encryption key (EDEK). Makes a call out to the Tenant Security Proxy to
     * decrypt the EDEK and then uses the resulting key (DEK) to encrypt the
     * document. This allows callers to update/re-encrypt data that has already been
     * encrypted with an existing key. For example, if multiple columns in a DB row
     * are all encrypted to the same key and one of those columns needs to be
     * updated, this method allows the caller to update a single column without
     * having to re-encrypt every field in the row with a new key.
     *
     * @param document PlaintextDocument which contains the encrypted document key
     *                 (EDEK) as well as the Map of bytes to encrypt.
     * @param metadata Metadata about the document being encrypted.
     * @return EncryptedDocument which contains a map of encrypted bytes and base64
     *         encrypted document key (EDEK).
     */
    public CompletableFuture<EncryptedDocument> encrypt(PlaintextDocument document, DocumentMetadata metadata) {
        return this.encryptionService.unwrapKey(document.getEdek(), metadata).thenApplyAsync(
                dek -> new EncryptedDocument(encryptFields(document.getDecryptedFields(), metadata, dek),
                        document.getEdek()),
                encryptionExecutor);
    }

    /**
     * Encrypt documents in parallel. Will generate a new document encryption key
     * for each item in the provided Collection and use it to encrypt all the fields
     * in the document Map. The provided metadata will be used for all encrypted
     * documents.
     *
     * @param documents Collection of documents to encrypt
     * @param metadata  Metadata about all of the documents being encrypted
     * @return List of EncryptedDocument instances in the same order (if ordered) as
     *         the plaintexts were provided.
     */
    public CompletableFuture<List<EncryptedDocument>> encryptBatch(Collection<Map<String, byte[]>> documents,
            DocumentMetadata metadata) {
        List<CompletableFuture<EncryptedDocument>> encryptOps = documents.stream()
                .map(plaintextDocument -> encrypt(plaintextDocument, metadata)).collect(Collectors.toList());

        return CompletableFutures.sequence(encryptOps);
    }

    /**
     * Encrypt the provided documents reusing an existing encrypted document
     * encryption key (EDEK). Makes a call out to the Tenant Security Proxy to
     * decrypt the EDEK and then uses the resulting key (DEK) to encrypt the
     * documents. This allows callers to batch update/re-encrypt data that has
     * already been encrypted with an existing key.
     *
     * @param documents Collection of PlaintextDocuments to re-encrypt
     * @param metadata  Metadata about all of the documents being encrypted
     * @return List of EncryptedDocument instances in the same order (if ordered) as
     *         the plaintexts were provided.
     */
    public CompletableFuture<List<EncryptedDocument>> encryptExistingBatch(Collection<PlaintextDocument> documents,
            DocumentMetadata metadata) {
        List<CompletableFuture<EncryptedDocument>> encryptOps = documents.stream()
                .map(plaintextDocument -> encrypt(plaintextDocument, metadata)).collect(Collectors.toList());

        return CompletableFutures.sequence(encryptOps);
    }

    /**
     * Decrypt the provided EncryptedDocument. Decrypts the documents encrypted
     * document key (EDEK) using the Tenant Security Proxy and uses it to decrypt
     * and return the document bytes. The DEK is then discarded.
     *
     * @param encryptedDocument Document to decrypt which includes encrypted bytes
     *                          as well as EDEK.
     * @param metadata          Metadata about the document being decrypted.
     * @return PlaintextDocument which contains each documents decrypted field
     *         bytes.
     */
    public CompletableFuture<PlaintextDocument> decrypt(EncryptedDocument encryptedDocument,
            DocumentMetadata metadata) {
        return this.encryptionService.unwrapKey(encryptedDocument.getEdek(), metadata)
                .thenApplyAsync(decryptedDocumentAESKey -> {
                    Map<String, byte[]> decryptedFields = decryptFields(encryptedDocument.getEncryptedFields(),
                            metadata, decryptedDocumentAESKey);
                    return new PlaintextDocument(decryptedFields, encryptedDocument.getEdek());
                });
    }

    /**
     * Decrypt the provided EncryptedDocuments in parallel. Returns a List of
     * PlaintextDocuments in the same order (if ordered) as provided. Uses the
     * provided metadata for each decrypt invocation.
     *
     * @param encryptedDocuments Collection of EncryptedDocuments to decrypt.
     * @param metadata           Metadata to use for each decrypt operation.
     * @return List of PlaintextDocuments in the same order as provided (if
     *         ordered).
     */
    public CompletableFuture<List<PlaintextDocument>> decryptBatch(Collection<EncryptedDocument> encryptedDocuments,
            DocumentMetadata metadata) {
        List<CompletableFuture<PlaintextDocument>> decryptOps = encryptedDocuments.stream()
                .map(encryptedDocument -> decrypt(encryptedDocument, metadata)).collect(Collectors.toList());

        return CompletableFutures.sequence(decryptOps);
    }
}