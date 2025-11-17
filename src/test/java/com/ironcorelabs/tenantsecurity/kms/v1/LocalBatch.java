package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import org.testng.annotations.Test;

@Test(groups = {"local-batch-integration"})
public class LocalBatch {
  private String TENANT_ID = System.getenv("TENANT_ID");
  private String API_KEY = System.getenv("API_KEY");

  private Map<String, byte[]> getRoundtripDataToEncrypt() {
    Map<String, byte[]> documentMap = new HashMap<>();
    try {
      documentMap.put("doc1", "Encrypt these bytes!".getBytes("UTF-8"));
      documentMap.put("doc2", "And these bytes!".getBytes("UTF-8"));
      documentMap.put("doc3", "And my axe!".getBytes("UTF-8"));
    } catch (Exception e) {
      // not possible
    }

    return documentMap;
  }

  private List<Map<String, byte[]>> getBatchList(int batchSize) {
    return Arrays.stream(new int[batchSize]).mapToObj(_nope -> getRoundtripDataToEncrypt())
        .collect(Collectors.toList());
  }

  private Map<String, Map<String, byte[]>> getBatchMap(int batchSize) {
    Map<String, Map<String, byte[]>> documentMap = new HashMap<>();
    List<Map<String, byte[]>> list = getBatchList(batchSize);
    for (int i = 0; i < list.size(); i++) {
      documentMap.put(Integer.toString(i), list.get(i));
    }
    return documentMap;
  }

  private void logFailures(Map<String, TenantSecurityException> failures) {
    if (failures.size() > 0) {
      System.out.println(String.format("Batch operation had %d failures", failures.size()));
      for (Map.Entry<String, TenantSecurityException> entry : failures.entrySet()) {
        System.out.println(String.format("%s: %s", entry.getKey(), entry.getValue()));
      }
    }
  }

  /**
   * Roundtrip a batch of 25 documents 50 times sequentially. Uses the new batch methods which send
   * a single request to the TSP per batch (1 request per batch * 50 runs = 50 total requests).
   */
  public void batchRoundtrip() throws Exception {
    DocumentMetadata context = new DocumentMetadata(this.TENANT_ID, "integrationTest", "sample");

    TenantSecurityClient client =
        new TenantSecurityClient.Builder(TestSettings.TSP_ADDRESS + TestSettings.TSP_PORT,
            this.API_KEY).build();

    int batchSize = 25;
    int batchRepetitions = 50;

    CompletableFuture<BatchResult<PlaintextDocument>> roundtrip =
        client.encryptBatch(getBatchMap(batchSize), context).thenCompose(encryptedResults -> {
          System.out.println("Run 1");
          logFailures(encryptedResults.getFailures());
          return client.decryptBatch(encryptedResults.getSuccesses(), context);
        });

    for (int i = 2; i <= batchRepetitions; i++) {
      final String run = "Run " + i;
      roundtrip =
          roundtrip.thenCompose(_nope -> client.encryptBatch(getBatchMap(batchSize), context))
              .thenCompose(encryptedResults -> {
                System.out.println(run);
                logFailures(encryptedResults.getFailures());
                return client.decryptBatch(encryptedResults.getSuccesses(), context);
              }).thenApply(decryptedResults -> {
                logFailures(decryptedResults.getFailures());
                return decryptedResults;
              });
    }

    try {
      long start = System.currentTimeMillis();
      roundtrip.get();
      System.out.println("Old Batch: " + (System.currentTimeMillis() - start));
    } catch (ExecutionException e) {
      System.out.println(e.getCause());
      if (e.getCause() instanceof TenantSecurityException) {
        TenantSecurityException kmsError = (TenantSecurityException) e.getCause();
        TenantSecurityErrorCodes errorCode = kmsError.getErrorCode();
        System.out.println("\nError Code: " + errorCode.getCode());
        System.out.println("\nError Code Info: " + errorCode.getMessage());
      }
      throw e;
    } finally {
      client.close();
    }
  }
}
