package com.ironcorelabs.simple;

import com.ironcorelabs.tenantsecurity.kms.v1.*;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

/**
 * Two examples:
 *
 * <p>Encrypt/Decrypt a customer record
 *
 * <p>Encrypt/Decrypt a file
 */
public class SimpleRoundtrip {

  // Change if you want to test against a non-local TSP.
  private static final String TSP_ADDR = "http://localhost:32804";

  public static void main(String[] args) throws Exception {

    // In order to communicate with the TSP, you need a matching API_KEY. Find the
    // right value from the end of the TSP configuration file, and set the API_KEY
    // environment variable to that value.
    String API_KEY = System.getenv("API_KEY");
    if (API_KEY == null) {
      System.out.println("Must set the API_KEY environment variable.");
      System.exit(1);
    }

    // default to "tenant-gcp-l". Override by setting the TENANT_ID environment variable
    String TENANT_ID = System.getenv("TENANT_ID");
    if (TENANT_ID == null) {
      TENANT_ID = "tenant-gcp-l";
    }
    System.out.println("Using tenant " + TENANT_ID);

    //
    // Example 1: encrypting/decrypting a customer record
    //

    // Create metadata used to associate this document to a tenant, name the document, and
    // identify the service or user making the call
    DocumentMetadata metadata = new DocumentMetadata(TENANT_ID, "serviceOrUserId", "PII");

    // Create a map containing your data
    Map<String, byte[]> custRecord = new HashMap<>();
    custRecord.put("ssn", "000-12-2345".getBytes("UTF-8"));
    custRecord.put("address", "2825-519 Stone Creek Rd, Bozeman, MT 59715".getBytes("UTF-8"));
    custRecord.put("name", "Jim Bridger".getBytes("UTF-8"));

    // Request a key from the KMS and use it to encrypt the document
    CompletableFuture<PlaintextDocument> roundtrip =
        // Initialize the client with a Tenant Security Proxy domain and API key.
        // Typically this would be done once when the application or service initializes
        TenantSecurityClient.create(TSP_ADDR, API_KEY)
            .thenCompose(
                client -> {
                  try {
                    return client
                        .encrypt(custRecord, metadata)
                        .thenCompose(
                            encryptedResults -> {
                              // persist the EDEK and encryptedDocument to your persistence layer
                              String edek = encryptedResults.getEdek();
                              Map<String, byte[]> encryptedDocument =
                                  encryptedResults.getEncryptedFields();

                              // un-comment if you want to print out the encrypted data
                              // System.out.println("Encrypted SSN: " + new
                              // String(encryptedDocument.get("ssn"), StandardCharsets.UTF_8));
                              // System.out.println("Encrypted address: " + new
                              // String(encryptedDocument.get("address"), StandardCharsets.UTF_8));
                              // System.out.println("Encrypted name: " + new
                              // String(encryptedDocument.get("name"), StandardCharsets.UTF_8));

                              // retrieve the EDEK and encryptedDocument from your persistence layer
                              EncryptedDocument retrievedEncryptedDocument =
                                  new EncryptedDocument(encryptedDocument, edek);

                              // decrypt back into plaintext
                              return client.decrypt(encryptedResults, metadata);
                            });
                  } catch (Exception e) {
                    throw new CompletionException(e);
                  }
                });

    try {
      // access decrypted fields
      Map<String, byte[]> decryptedValuesMap = roundtrip.get().getDecryptedFields();

      System.out.println(
          "Decrypted SSN: " + new String(decryptedValuesMap.get("ssn"), StandardCharsets.UTF_8));
      System.out.println(
          "Decrypted address: "
              + new String(decryptedValuesMap.get("address"), StandardCharsets.UTF_8));
      System.out.println(
          "Decrypted name: " + new String(decryptedValuesMap.get("name"), StandardCharsets.UTF_8));
    } catch (ExecutionException e) {
      if (e.getCause() instanceof TenantSecurityException) {
        TenantSecurityException kmsError = (TenantSecurityException) e.getCause();
        TenantSecurityErrorCodes errorCode = kmsError.getErrorCode();
        System.out.println("\nError Message: " + kmsError.getMessage());
        System.out.println("\nError Code: " + errorCode.getCode());
        System.out.println("\nError Code Info: " + errorCode.getMessage() + "\n");
      }
      throw e;
    }

    //
    // Example 2: encrypting/decrypting a file, using the filesystem for persistence
    //

    String sourceFile = "success.jpg";
    byte[] sourceFileBytes = Files.readAllBytes(Paths.get(sourceFile));
    Map<String, byte[]> toEncrypt = new HashMap<>();
    toEncrypt.put("file", sourceFileBytes);

    // Request a key from the KMS and use it to encrypt the document
    CompletableFuture<PlaintextDocument> roundtripFile =
        // Initialize the client with a Tenant Security Proxy domain and API key.
        // Typically this would be done once when the application or service initializes
        TenantSecurityClient.create(TSP_ADDR, API_KEY)
            .thenCompose(
                client -> {
                  try {
                    return client
                        .encrypt(toEncrypt, metadata)
                        .thenCompose(
                            encryptedResults -> {
                              // write the encrypted file and the encrypted key to the filesystem
                              try {
                                Files.write(
                                    Paths.get(sourceFile + ".enc"),
                                    encryptedResults.getEncryptedFields().get("file"));
                                Files.write(
                                    Paths.get(sourceFile + ".edek"),
                                    encryptedResults.getEdek().getBytes(StandardCharsets.UTF_8));
                              } catch (IOException e) {
                                throw new CompletionException(e);
                              }

                              // some time later... read the file from the disk
                              try {
                                byte[] encryptedBytes =
                                    Files.readAllBytes(Paths.get(sourceFile + ".enc"));
                                byte[] encryptedDek =
                                    Files.readAllBytes(Paths.get(sourceFile + ".edek"));

                                EncryptedDocument fileAndEdek =
                                    new EncryptedDocument(
                                        Collections.singletonMap("file", encryptedBytes),
                                        new String(encryptedDek, StandardCharsets.UTF_8));

                                // decrypt
                                return client.decrypt(fileAndEdek, metadata);

                              } catch (IOException e) {
                                throw new CompletionException(e);
                              }
                            });
                  } catch (Exception e) {
                    throw new CompletionException(e);
                  }
                });

    try {
      // write the decrypted file back to the filesystem
      Files.write(Paths.get("decrypted.jpg"), roundtripFile.get().getDecryptedFields().get("file"));
    } catch (ExecutionException e) {
      if (e.getCause() instanceof TenantSecurityException) {
        TenantSecurityException kmsError = (TenantSecurityException) e.getCause();
        TenantSecurityErrorCodes errorCode = kmsError.getErrorCode();
        System.out.println("\nError Message: " + kmsError.getMessage());
        System.out.println("\nError Code: " + errorCode.getCode());
        System.out.println("\nError Code Info: " + errorCode.getMessage() + "\n");
      }
      throw e;
    }

    System.exit(0);
  }
}
