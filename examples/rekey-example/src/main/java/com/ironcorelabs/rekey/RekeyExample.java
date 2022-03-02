package com.ironcorelabs.rekey;

import com.ironcorelabs.tenantsecurity.kms.v1.*;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

/**
 * Three parts:
 *
 * <p>Encrypt a customer record
 *
 * <p>Rekey the encrypted record to a new tenant
 *
 * <p>Decrypt the encrypted record using the new tenant
 */
public class RekeyExample {

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

    // default encrypting to tenant "tenant-gcp". Override by setting the TENANT_ID environment
    // variable
    String tenantId = System.getenv("TENANT_ID");
    if (tenantId == null) {
      tenantId = "tenant-gcp";
    }
    final String TENANT_ID = tenantId;

    // Initialize the client with a Tenant Security Proxy domain and API key.
    // Typically this would be done once when the application or service initializes.
    CompletableFuture<PlaintextDocument> rekeyedRoundtrip =
        TenantSecurityClient.create(TSP_ADDR, API_KEY)
            .thenCompose(
                client -> {
                  try {
                    //
                    // Part 1: Encrypting a customer record
                    //

                    // Create metadata used to associate this document to the first tenant, name the
                    // document, and identify the service or user making the call
                    DocumentMetadata metadata =
                        new DocumentMetadata(TENANT_ID, "serviceOrUserId", "PII");

                    // Create a map containing your data
                    Map<String, byte[]> custRecord = new HashMap<>();
                    custRecord.put("ssn", "000-12-2345".getBytes("UTF-8"));
                    custRecord.put(
                        "address", "2825-519 Stone Creek Rd, Bozeman, MT 59715".getBytes("UTF-8"));
                    custRecord.put("name", "Jim Bridger".getBytes("UTF-8"));

                    System.out.println("Encrypting using tenant " + TENANT_ID);
                    // Request a key from the KMS and use it to encrypt the document
                    CompletableFuture<EncryptedDocument> encryptedDocument =
                        client.encrypt(custRecord, metadata);

                    //
                    // Part 2: Rekey the encrypted record to a new tenant
                    //

                    final String NEW_TENANT_ID = "tenant-aws";

                    System.out.println("Rekeying to tenant " + NEW_TENANT_ID);

                    CompletableFuture<EncryptedDocument> rekeyedDocument =
                        encryptedDocument.thenCompose(
                            // Rekey the document to `tenant-aws` using their primary config. The
                            // metadata's name and identifying information could also be changed at
                            // this time.
                            encrypted -> 
                                client.rekeyEdek(encrypted.getEdek(), metadata, NEW_TENANT_ID)
                                    .thenApply(
                                        newDoc -> 
                                            new EncryptedDocument(encrypted.getEncryptedFields(), 
                                                                  newDoc)
                                ));
                                    
                                    

                    //
                    // Part 3: Decrypt the encrypted record using the new tenant
                    //

                    // Create new metadata for this document indicating that it was
                    // rekeyed to the second tenant. The name and identifying information
                    // could also be changed at this time.
                    DocumentMetadata newMetadata =
                        new DocumentMetadata(NEW_TENANT_ID, "serviceOrUserId", "PII");

                    System.out.println("Decrypting with tenant " + NEW_TENANT_ID);

                    CompletableFuture<PlaintextDocument> decryptedDocument =
                        rekeyedDocument.thenCompose(
                            // Decrypt the document encrypted to `tenant-aws`
                            rekeyed -> client.decrypt(rekeyed, newMetadata));

                    return decryptedDocument;
                  } catch (Exception e) {
                    throw new CompletionException(e);
                  }
                });

    try {
      // access decrypted fields
      Map<String, byte[]> decryptedValuesMap = rekeyedRoundtrip.get().getDecryptedFields();

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
    System.exit(0);
  }
}
