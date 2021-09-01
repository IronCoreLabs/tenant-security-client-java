package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ironcorelabs.proto.DocumentHeader;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.CryptoException;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

class CryptoUtils {
    static final String AES_ALGO = "AES/GCM/NoPadding";
    public static final int IV_BYTE_LENGTH = 12;
    static final int GCM_TAG_BIT_LENGTH = 128;
    // the size of the fixed length portion of the header (version, magic, size)
    static final int DOCUMENT_HEADER_META_LENGTH = 7;
    static final byte CURRENT_DOCUMENT_HEADER_VERSION = 3;
    static final int GCM_TAG_BYTE_LEN = GCM_TAG_BIT_LENGTH / 8;

    static final byte[] DOCUMENT_MAGIC = { 73, 82, 79, 78 }; // bytes for ASCII IRON
                                                             // characters

    static final int HEADER_META_LENGTH_LENGTH = 2;
    // The number of fixed size bytes of header at the front of all CMK documents.
    // After this length is the probobuf-encoded header bytes, which
    // might be empty.
    static final int HEADER_FIXED_SIZE_CONTENT_LENGTH = 1 + DOCUMENT_MAGIC.length + HEADER_META_LENGTH_LENGTH;
    // How many bytes to read in each loop when doing streaming encryption.
    static final int STREAM_CHUNKING = 256 * 1024;
    static final int MAX_HEADER_SIZE = 65535; // 256 * 255 + 255 since we do a 2 byte size.

    public static class V3HeaderSignature {
        private final byte[] iv;
        private final byte[] gcmTag;

        public V3HeaderSignature(byte[] iv, byte[] gcmTag) {
            this.iv = iv;
            this.gcmTag = gcmTag;
        }

        public ByteBuffer getIv() {
            return ByteBuffer.wrap(iv);
        }

        public ByteBuffer getGcmTag() {
            return ByteBuffer.wrap(gcmTag);
        }

        public byte[] getSig() {
            byte[] result = new byte[IV_BYTE_LENGTH + GCM_TAG_BYTE_LEN];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(gcmTag, 0, result, iv.length, gcmTag.length);
            return result;
        }
    }

    public static CompletableFuture<Void> encryptStreamInternal(byte[] documentKey, DocumentMetadata metadata,
            InputStream input, OutputStream output, SecureRandom secureRandom) {
        byte[] iv = new byte[IV_BYTE_LENGTH];
        secureRandom.nextBytes(iv);
        return generateHeader(documentKey, metadata, secureRandom).thenCompose(headerBytes -> {
            return CompletableFutures.tryCatchNonFatal(() -> {
                byte[] bytesRead = new byte[0];
                Cipher cipher = getNewAesCipher(documentKey, iv, true);
                output.write(headerBytes);
                output.write(iv);
                while ((bytesRead = readNBytes(input, STREAM_CHUNKING)).length != 0) {
                    byte[] encryptedBytes = cipher.update(bytesRead);
                    output.write(encryptedBytes);
                }
                // Final bytes, which might be buffered data or just the GCM tag.
                byte[] finalBytes = cipher.doFinal();
                output.write(finalBytes);
                return null; // This is the only value that inhabits Void. I'm sorry.
            });
        });
    }

    public static CompletableFuture<Void> decryptStreamInternal(byte[] documentKey, InputStream encryptedStream,
            OutputStream decryptedStream) {
        return getHeaderFromStream(encryptedStream).thenCompose(header -> {
            return verifyHeaderProto(documentKey, header).thenCompose(verification -> {
                return CompletableFutures.tryCatchNonFatal(() -> {
                    if (!verification) {
                        throw new CryptoException(
                                "The signature computed did not match. Likely that the documentKey is incorrect.");
                    }
                    byte[] iv = readNBytes(encryptedStream, IV_BYTE_LENGTH);
                    if (iv.length != IV_BYTE_LENGTH) {
                        throw new CryptoException("IV not found on the front of the encrypted document.");
                    }
                    Cipher cipher = getNewAesCipher(documentKey, iv, false);
                    byte[] currentChunk = new byte[0];
                    while ((currentChunk = readNBytes(encryptedStream, STREAM_CHUNKING)).length > 0) {
                        decryptedStream.write(cipher.update(currentChunk));
                    }
                    decryptedStream.write(cipher.doFinal());
                    return null;
                });
            });

        });

    }

    public static Cipher getNewAesCipher(byte[] documentKey, byte[] iv, boolean encryptMode) throws Exception {
        final Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(encryptMode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(documentKey, "AES"),
                new GCMParameterSpec(GCM_TAG_BIT_LENGTH, iv));
        return cipher;
    }

    /**
     * Given the provided document bytes and an AES key, encrypt and return the
     * encrypted bytes.
     */
    public static CompletableFuture<byte[]> encryptBytes(byte[] document, DocumentMetadata metadata, byte[] documentKey,
            SecureRandom secureRandom) {

        // Create the output at a reasonable size. This means that the header can be up
        // to 512 bytes of content without growing. This is a very comfortable upper
        // bound for v3 header as only the tenant id is in there. If it needs to, the
        // stream can grow, but this should help limit allocations.
        ByteArrayOutputStream output = new ByteArrayOutputStream(
                document.length + IV_BYTE_LENGTH + GCM_TAG_BYTE_LEN + HEADER_FIXED_SIZE_CONTENT_LENGTH + 512);
        return encryptStreamInternal(documentKey, metadata, new ByteArrayInputStream(document), output, secureRandom)
                .thenApply(unused -> {
                    return output.toByteArray();
                });
    }

    /**
     * Decrypt a ICL document and return the plaintext.
     *
     * @param encryptedDocument The encrypted document including the ICL document
     *                          header.
     * @param documentKey       The AES key to decrypt the document.
     * @return A future with the document decrypted.
     */
    public static CompletableFuture<byte[]> decryptDocument(byte[] encryptedDocumentBytes, byte[] documentKey) {
        ByteArrayInputStream encryptedStream = new ByteArrayInputStream(encryptedDocumentBytes);
        ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream(encryptedDocumentBytes.length);
        return decryptStreamInternal(documentKey, encryptedStream, decryptedStream)
                .thenApply(unused -> decryptedStream.toByteArray());

    }

    /**
     * Generate a header to mark the encrypted document as ours.
     * 
     * Current version is as follows: VERSION_NUMBER (1 bytes, fixed at 3),
     * IRONCORE_MAGIC (4 bytes, IRON in ASCII), HEADER_LENGTH (2 bytes Uint16),
     * PROTOBUF_HEADER_DATA (variable bytes)
     * 
     */
    static CompletableFuture<byte[]> generateHeader(byte[] documentKey, DocumentMetadata metadata,
            SecureRandom secureRandom) {
        final byte headerVersion = CURRENT_DOCUMENT_HEADER_VERSION;
        final byte[] magic = DOCUMENT_MAGIC;
        return createHeaderProto(documentKey, metadata, secureRandom)
                .thenCompose(proto -> CompletableFutures.tryCatchNonFatal(() -> {
                    ByteArrayOutputStream saasHeaderOutput = new ByteArrayOutputStream();
                    proto.writeTo(saasHeaderOutput);
                    byte[] saasHeaderBytes = saasHeaderOutput.toByteArray();
                    if (saasHeaderBytes.length > MAX_HEADER_SIZE) {
                        throw new CryptoException(
                                "The header is too large. It is " + saasHeaderBytes.length + " bytes long.");
                    }
                    int firstByte = saasHeaderBytes.length / 256;
                    int secondByte = saasHeaderBytes.length % 256;
                    final byte[] headerSize = { (byte) firstByte, (byte) secondByte };
                    return ByteBuffer.allocate(DOCUMENT_HEADER_META_LENGTH + saasHeaderBytes.length).put(headerVersion)
                            .put(magic).put(headerSize).put(saasHeaderBytes).array();
                }));
    }

    /**
     * Get the header bytes off of the stream. This will mutate the stream and read
     * up until the cipher text with the IV on the front of it.
     *
     * @param inputStream The input stream to read the header from.
     * @return The document header.
     */
    static CompletableFuture<DocumentHeader.v3DocumentHeader> getHeaderFromStream(InputStream inputStream) {
        return CompletableFutures.tryCatchNonFatal(() -> {
            byte[] fixedPreamble = readNBytes(inputStream, HEADER_FIXED_SIZE_CONTENT_LENGTH);
            if (!isCiphertext(fixedPreamble)) {
                throw new IllegalArgumentException("Provided bytes were not an Ironcore encrypted document.");
            } else {
                // This call is safe only because it's in the else of the cyphertext check.
                int headerLength = getHeaderSize(fixedPreamble);
                byte[] headerBytes = readNBytes(inputStream, headerLength);
                InputStream headerStream = new ByteArrayInputStream(headerBytes);
                return DocumentHeader.v3DocumentHeader.parseFrom(headerStream);
            }
        });
    }

    static CompletableFuture<DocumentHeader.v3DocumentHeader> createHeaderProto(byte[] documentKey,
            DocumentMetadata metadata, SecureRandom secureRandom) {

        DocumentHeader.SaaSShieldHeader saasHeader = DocumentHeader.SaaSShieldHeader.newBuilder()
                .setTenantId(metadata.getTenantId()).build();
        byte[] iv = new byte[IV_BYTE_LENGTH];
        secureRandom.nextBytes(iv);
        return generateSignature(documentKey, iv, saasHeader).thenApply(sig -> {
            return DocumentHeader.v3DocumentHeader.newBuilder().setSaasShield(saasHeader)
                    .setSig(com.google.protobuf.ByteString.copyFrom(sig.getSig())).build();

        });
    }

    static CompletableFuture<V3HeaderSignature> generateSignature(byte[] documentKey, byte[] iv,
            DocumentHeader.SaaSShieldHeader header) {
        return CompletableFutures.tryCatchNonFatal(() -> {
            ByteArrayOutputStream saasHeaderOutput = new ByteArrayOutputStream();
            header.writeTo(saasHeaderOutput);
            byte[] saasHeaderBytes = saasHeaderOutput.toByteArray();
            Cipher encryptCipher = getNewAesCipher(documentKey, iv, true);
            byte[] encryptResult = encryptCipher.doFinal(saasHeaderBytes);
            byte[] tag = new byte[GCM_TAG_BYTE_LEN];
            ByteBuffer.wrap(encryptResult, encryptResult.length - GCM_TAG_BYTE_LEN, GCM_TAG_BYTE_LEN).get(tag);
            return new V3HeaderSignature(iv, tag);
        });
    }

    static CompletableFuture<Boolean> verifyHeaderProto(byte[] documentKey, DocumentHeader.v3DocumentHeader header) {
        // Note that this is mutable and will be pulled off in both futures. They're
        // sequenced so it's safe to do so.
        ByteBuffer sigBuffer = header.getSig().asReadOnlyByteBuffer();
        if (sigBuffer.remaining() == 0) {
            return CompletableFuture.completedFuture(true);
        } else {
            return CompletableFutures.tryCatchNonFatal(() -> {
                if (sigBuffer.remaining() != IV_BYTE_LENGTH + GCM_TAG_BYTE_LEN) {
                    throw new CryptoException("Signature was not well formed.");
                }
                if (header.getSaasShield() == null) {
                    throw new CryptoException("Header was invalid.");
                }
                return null; // Future of void has to be null.
            }).thenCompose(thisIsNull -> {
                byte[] iv = new byte[IV_BYTE_LENGTH];
                byte[] gcmTag = new byte[GCM_TAG_BYTE_LEN];

                // Fill out the iv and gcmTag arrays, which should always succeed because we
                // checked above that the buffer is what we expect.
                sigBuffer.get(iv);
                sigBuffer.get(gcmTag);
                return generateSignature(documentKey, iv, header.getSaasShield())
                        .thenApply(computedGcmBuffer -> computedGcmBuffer.getGcmTag().equals(ByteBuffer.wrap(gcmTag)));
            });
        }
    }

    /**
     * Multiply the header size bytes at the 5th and 6th indices to get the header
     * size. If those bytes don't exist this will throw.
     */
    static int getHeaderSize(byte[] bytes) {
        return (bytes[5] & 0xFF) * 256 + (bytes[6] & 0xFF);
    }

    /**
     * Check if an IronCore header is present in some bytes, indicating that it is
     * ciphertext.
     *
     * @param bytes bytes to be checked
     */
    public static boolean isCiphertext(byte[] bytes) {
        // Header size is variable for CMK encrypted docs depending on whether
        // the header is present. Expect at least one byte following the header
        // that would have been encrypted.
        return bytes.length >= DOCUMENT_HEADER_META_LENGTH && bytes[0] == CURRENT_DOCUMENT_HEADER_VERSION
                && containsIroncoreMagic(bytes) && getHeaderSize(bytes) >= 0;
    }

    /**
     * Check that the given bytes contain 4 bytes of ASCII representing "IRON"
     * document magic. This magic should start at index 1, after the expected header
     * version byte.
     */
    static boolean containsIroncoreMagic(byte[] bytes) {
        return bytes.length >= 5 && ByteBuffer.wrap(bytes, 1, 4).compareTo(ByteBuffer.wrap(DOCUMENT_MAGIC)) == 0;
    }

    /**
     * Read up to len bytes from the inputStream and return them.
     * 
     * @param inputStream The input stream to read from.
     * @param len         The number of bytes to read.
     * @return bytes read from the input stream.
     * @throws IOException If length is less than 0 or if
     */
    static byte[] readNBytes(InputStream inputStream, int len) throws IOException {
        if (len < 0) {
            throw new IllegalArgumentException("length cannot be < 0.");
        }
        int remaining = len;
        byte[] result = new byte[remaining];
        int bytesRead = inputStream.read(result);

        if (bytesRead > 0) {
            return result.length == bytesRead ? result : java.util.Arrays.copyOf(result, bytesRead);
        } else {
            return new byte[0];
        }
    }
}
