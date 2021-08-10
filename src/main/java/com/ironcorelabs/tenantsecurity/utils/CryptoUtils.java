package com.ironcorelabs.tenantsecurity.utils;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.ironcorelabs.tenantsecurity.kms.v1.StreamingResponse;

public class CryptoUtils {
    static final String AES_ALGO = "AES/GCM/NoPadding";
    public static final int IV_BYTE_LENGTH = 12;
    static final int GCM_TAG_BIT_LENGTH = 128;
    // the size of the fixed length portion of the header (version, magic, size)
    static final int DOCUMENT_HEADER_META_LENGTH = 7;
    static final byte CURRENT_DOCUMENT_HEADER_VERSION = 3;
    static final byte[] DOCUMENT_MAGIC = { 73, 82, 79, 78 }; // bytes for ASCII IRON
                                                             // characters

    static final int HEADER_META_LENGTH_LENGTH = 2;
    // The number of fixed size bytes of header at the front of all CMK documents.
    // After this length is the probobuf-encoded header bytes, which
    // might be empty.
    static final int HEADER_FIXED_SIZE_CONTENT_LENGTH = 1 + DOCUMENT_MAGIC.length + HEADER_META_LENGTH_LENGTH;
    // How many bytes to read in each loop when doing streaming encryption.
    static final int STREAM_CHUNKING = 32;

    public static CompletableFuture<Boolean> encryptStreamInternal(byte[] documentKey, InputStream input,
            OutputStream output, SecureRandom secureRandom) {
        byte[] iv = new byte[IV_BYTE_LENGTH];
        secureRandom.nextBytes(iv);

        return CompletableFutures.tryCatchNonFatal(() -> {
            byte[] bytesRead = new byte[0];
            Cipher cipher = getNewAesCipher(documentKey, iv, true);
            output.write(generateHeader());
            output.write(iv);
            while ((bytesRead = input.readNBytes(STREAM_CHUNKING)).length != 0) {
                byte[] encryptedBytes = cipher.update(bytesRead);
                output.write(encryptedBytes);
            }
            // Final bytes, which might be buffered data or just the GCM tag.
            byte[] finalBytes = cipher.doFinal();
            output.write(finalBytes);
            return true;
        });
    }

    public static CompletableFuture<Boolean> decryptStreamInternal(byte[] documentKey, InputStream encryptedStream,
            OutputStream decryptedStream) {
        // TODO really get the header and use it for something
        return getHeaderFromStream(encryptedStream).thenCompose(header -> {
            return CompletableFutures.tryCatchNonFatal(() -> {
                byte[] iv = encryptedStream.readNBytes(IV_BYTE_LENGTH);
                // TODO do we need to check that the iv isn't empty?
                Cipher cipher = getNewAesCipher(documentKey, iv, false);
                byte[] currentChunk = new byte[0];
                int GCM_TAG_BYTE_LEN = GCM_TAG_BIT_LENGTH / 8;
                PushbackInputStream pushbackStream = new PushbackInputStream(encryptedStream, GCM_TAG_BYTE_LEN + 1);
                while ((currentChunk = pushbackStream.readNBytes(STREAM_CHUNKING)).length > 0) {
                    ;
                    // Check to see if there is at least 1 byte more than the GCM tag so we know
                    // that
                    // the next loop won't read less than the GCM tag.
                    byte[] maybeTagBytes = pushbackStream.readNBytes(GCM_TAG_BYTE_LEN + 1);
                    if (maybeTagBytes.length <= GCM_TAG_BYTE_LEN) {
                        decryptedStream.write(cipher.doFinal(ByteBuffer.wrap(currentChunk).put(maybeTagBytes).array()));
                    } else {
                        decryptedStream.write(cipher.update(currentChunk));
                        pushbackStream.unread(maybeTagBytes);
                    }
                }
                return true;
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
    public static CompletableFuture<byte[]> encryptBytes(byte[] document, byte[] documentKey,
            SecureRandom secureRandom) {
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
     * Given the provided encrypted document (which has an IV prepended to it) and
     * an AES key, decrypt and return the decrypted bytes.
     */
    public static CompletableFuture<byte[]> decryptBytes(ByteBuffer encryptedDocument, byte[] documentKey) {
        byte[] iv = new byte[CryptoUtils.IV_BYTE_LENGTH];

        // Pull out the IV from the front of the encrypted data
        encryptedDocument.get(iv);
        byte[] encryptedBytes = new byte[encryptedDocument.remaining()];
        encryptedDocument.get(encryptedBytes);

        return CompletableFutures.tryCatchNonFatal(() -> {
            final Cipher cipher = CryptoUtils.getNewAesCipher(documentKey, iv, false);
            return cipher.doFinal(encryptedBytes);
        });
    }

    /**
     * Generate a header to mark the encrypted document as ours. Right now this is
     * all constant; in the future this will contain a protobuf bytes header of
     * variable length.
     */
    static byte[] generateHeader() {
        final byte headerVersion = CURRENT_DOCUMENT_HEADER_VERSION;
        final byte[] magic = DOCUMENT_MAGIC;
        final byte[] headerSize = { (byte) 0, (byte) 0 };
        return ByteBuffer.allocate(DOCUMENT_HEADER_META_LENGTH).put(headerVersion).put(magic).put(headerSize).array();
    }

    /**
     * Get the header bytes off of the stream. This will mutate the stream and read
     * up until the cipher text with the IV on the front of it.
     * 
     * @param inputStream
     * @return
     */
    static CompletableFuture<Integer> getHeaderFromStream(InputStream inputStream) {
        return CompletableFutures.tryCatchNonFatal(() -> {
            byte[] fixedPreamble = inputStream.readNBytes(HEADER_FIXED_SIZE_CONTENT_LENGTH);
            if (!isCiphertext(fixedPreamble)) {
                throw new IllegalArgumentException("Provided bytes were not an Ironcore encrypted document.");
            } else {
                // This call is safe only because it's in the else of the cyphertext check.
                int headerLength = getHeaderSize(fixedPreamble);
                byte[] headerBytes = inputStream.readNBytes(headerLength);
                return headerBytes.length;
            }
        });
    }

    /**
     * Multiply the header size bytes at the 5th and 6th indices to get the header
     * size. If those bytes don't exist this will throw.
     */
    static int getHeaderSize(byte[] bytes) {
        return bytes[5] * 256 + bytes[6];
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
     * Parses the header off the encrypted document and returns a ByteBuffer
     * wrapping the document bytes. Once the header contains metadata we care about,
     * this will return a class containing the document bytes and the header.
     */
    public static CompletableFuture<ByteBuffer> parseDocumentParts(byte[] document) {
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
     * Check that the given bytes contain 4 bytes of ASCII representing "IRON"
     * document magic. This magic should start at index 1, after the expected header
     * version byte.
     */
    static boolean containsIroncoreMagic(byte[] bytes) {
        return bytes.length >= 5 && ByteBuffer.wrap(bytes, 1, 4).compareTo(ByteBuffer.wrap(DOCUMENT_MAGIC)) == 0;
    }
}
