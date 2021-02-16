package com.ironcorelabs.simple;

import com.ironcorelabs.tenantsecurity.kms.v1.DocumentMetadata;
import com.ironcorelabs.tenantsecurity.kms.v1.PlaintextDocument;
import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityClient;
import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityErrorCodes;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

public class SimpleRoundtrip {

    private static final String API_KEY="0WUaXesNgbTAuLwn";
    private static final String TENANT_ID = "tenant-gcp-l";
    private static final String TSP_ADDR = "http://localhost:32804";

    public static void main(String[] args) throws Exception {
        System.out.println("Hey");

        System.out.println("Using tenant " + TENANT_ID);


        //
        // Example 1: encrypting/decrypting a customer record
        //

        // Create metadata used to associate this document to a tenant, name the document, and
        // identify the service or user making the call
        DocumentMetadata metadata = new DocumentMetadata(TENANT_ID, "serviceOrUserId", "PII");

        Map<String, byte[]> custRecord = new HashMap<>();
        custRecord.put("ssn", "000-12-2345".getBytes("UTF-8"));
        custRecord.put("address", "2825-519 Stone Creek Rd, Bozeman, MT 59715".getBytes("UTF-8"));
        custRecord.put("name", "Jim Bridger".getBytes("UTF-8"));




        CompletableFuture<PlaintextDocument> roundtrip =
                // Initialize the client with a Tenant Security Proxy domain and API key.
                // Typically this would be done once when the application or service initializes
                TenantSecurityClient.create(TSP_ADDR, API_KEY).thenCompose(client -> {

                    try {
                        return client.encrypt(custRecord, metadata)
                                .thenCompose(encryptedResults -> {
                                    System.out.println(encryptedResults.getEdek());
                                    Map<String, byte[]> fields =
                                            encryptedResults.getEncryptedFields();
                                    System.out.println(Arrays.toString(fields.get("ssn")));
                                    System.out.println(Arrays.toString(fields.get("address")));
                                    System.out.println(Arrays.toString(fields.get("name")));
                                    return client.decrypt(encryptedResults, metadata);
                                });
                    } catch (Exception e) {
                        throw new CompletionException(e);
                    }
                });

        try {
            Map<String, byte[]> decryptedValuesMap = roundtrip.get().getDecryptedFields();

            System.out.println("Decrypted SSN: " + new String(decryptedValuesMap.get("ssn"), StandardCharsets.UTF_8));
            System.out.println("Decrypted address: " + new String(decryptedValuesMap.get("address"), StandardCharsets.UTF_8));
            System.out.println("Decrypted name: " + new String(decryptedValuesMap.get("name"), StandardCharsets.UTF_8));
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
