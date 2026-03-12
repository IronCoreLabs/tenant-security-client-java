package com.ironcorelabs.cachedkey;

import com.ironcorelabs.tenantsecurity.kms.v1.*;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

/**
 * Demonstrates using CachedEncryptor and CachedDecryptor to encrypt/decrypt multiple records with a
 * single TSP call.
 */
public class CachedKeyExample {

  private static final String TSP_ADDR = "http://localhost:32804";

  public static void main(String[] args) throws Exception {

    String API_KEY = System.getenv("API_KEY");
    if (API_KEY == null) {
      System.out.println("Must set the API_KEY environment variable.");
      System.exit(1);
    }

    String tenantId = System.getenv("TENANT_ID");
    if (tenantId == null) {
      tenantId = "tenant-gcp-l";
    }
    System.out.println("Using tenant " + tenantId);

    TenantSecurityClient client =
        new TenantSecurityClient.Builder(TSP_ADDR, API_KEY).allowInsecureHttp(true).build();

    DocumentMetadata metadata = new DocumentMetadata(tenantId, "serviceOrUserId", "PII");

    // Simulate a database table: each row has an encrypted record and its EDEK
    List<Map<String, byte[]>> encryptedRows = new ArrayList<>();
    String sharedEdek;

    // Encrypt: one TSP call, then N local encrypts
    //
    // In a real application this block would be inside a database transaction. The
    // createCachedEncryptor call is the only network round trip — every encrypt() after
    // that is purely local CPU work, so it won't add latency or failure modes to the
    // transaction.
    try (CachedEncryptor encryptor = client.createCachedEncryptor(metadata).get()) {
      String[][] customers =
          {{"000-12-2345", "2825-519 Stone Creek Rd, Bozeman, MT 59715", "Jim Bridger"},
              {"000-45-6789", "100 Main St, Helena, MT 59601", "John Colter"},
              {"000-98-7654", "742 Evergreen Terrace, Missoula, MT 59801", "Sacagawea"},};

      for (String[] customer : customers) {
        Map<String, byte[]> record = new HashMap<>();
        record.put("ssn", customer[0].getBytes(StandardCharsets.UTF_8));
        record.put("address", customer[1].getBytes(StandardCharsets.UTF_8));
        record.put("name", customer[2].getBytes(StandardCharsets.UTF_8));

        // This encrypt is local — no TSP call
        EncryptedDocument encrypted = encryptor.encrypt(record, metadata).get();
        encryptedRows.add(encrypted.getEncryptedFields());
      }

      // All rows share this EDEK; store it alongside the rows (or once per batch)
      sharedEdek = encryptor.getEdek();

      System.out
          .println("Encrypted " + encryptor.getOperationCount() + " records with one TSP call");
    }
    // leaving the `try` block zeroes the DEK and reports usage to the TSP

    // Decrypt: one TSP call, then N local decrypts
    try (CachedDecryptor decryptor = client.createCachedDecryptor(sharedEdek, metadata).get()) {
      for (Map<String, byte[]> row : encryptedRows) {
        EncryptedDocument doc = new EncryptedDocument(row, sharedEdek);

        // This decrypt is local — no TSP call
        PlaintextDocument plaintext = decryptor.decrypt(doc, metadata).get();
        Map<String, byte[]> fields = plaintext.getDecryptedFields();

        System.out.println("Decrypted: " + new String(fields.get("name"), StandardCharsets.UTF_8)
            + " / " + new String(fields.get("ssn"), StandardCharsets.UTF_8));
      }

      System.out
          .println("Decrypted " + decryptor.getOperationCount() + " records with one TSP call");
    }

    System.exit(0);
  }
}
