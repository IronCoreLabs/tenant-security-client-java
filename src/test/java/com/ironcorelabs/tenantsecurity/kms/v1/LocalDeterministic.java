package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.CryptoException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;
import org.testng.annotations.Test;

@Test(groups = {"local-deterministic"})
public class LocalDeterministic {
  // Default values that can be overridden by environment variables of the same name
  // These match up to the Demo TSP whose config we ship with the repo.
  private static String TENANT_ID = "";
  private static String API_KEY = "";

  private void assertEqualBytes(byte[] one, byte[] two) throws Exception {
    assertEquals(new String(one, "UTF-8"), new String(two, "UTF-8"));
  }

  private DeterministicPlaintextField getRoundtripDataToEncrypt() {
    return new DeterministicPlaintextField("Encrypt these bytes!".getBytes(), "deriv_path",
        "secret_path");
  }

  private CompletableFuture<DeterministicTenantSecurityClient> createClient() {
    return CompletableFutures.tryCatchNonFatal(() -> {
      Map<String, String> envVars = System.getenv();
      String tsp_address = envVars.getOrDefault("TSP_ADDRESS", TestSettings.TSP_ADDRESS);
      String tsp_port = envVars.getOrDefault("TSP_PORT", TestSettings.TSP_PORT);
      String api_key = envVars.getOrDefault("API_KEY", API_KEY);

      if (tsp_port.charAt(0) != ':') {
        tsp_port = ":" + tsp_port;
      }
      return new DeterministicTenantSecurityClient(tsp_address + tsp_port, api_key,
          DeterministicTenantSecurityClient.DEFAULT_REQUEST_THREADPOOL_SIZE, 1);
    });
  }

  public void roundtripTest() throws Exception {
    String tenant_id = System.getenv().getOrDefault("TENANT_ID", TENANT_ID);

    DocumentMetadata context = new DocumentMetadata(tenant_id, "integrationTest", "sample",
        new HashMap<>(), "customRayID");
    DeterministicPlaintextField data = getRoundtripDataToEncrypt();

    CompletableFuture<DeterministicPlaintextField> roundtrip =
        createClient().thenCompose(client -> client.encrypt(data, context)
            .thenCompose(encryptedResults -> client.decrypt(encryptedResults, context)));

    try {
      DeterministicPlaintextField decryptedField = roundtrip.get();
      assertEquals(decryptedField.getDerivationPath(), data.getDerivationPath());
      assertEquals(decryptedField.getSecretPath(), data.getSecretPath());
      assertEqualBytes(decryptedField.getPlaintextField(), data.getPlaintextField());
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
  }

  private Map<String, DeterministicPlaintextField> getBatchMap(int batchSize) {
    Map<String, DeterministicPlaintextField> documentMap = new HashMap<>();
    for (int i = 0; i < batchSize; i++) {
      documentMap.put(Integer.toString(i), getRoundtripDataToEncrypt());
    }
    return documentMap;
  }

  public void batchRoundtripTest() throws Exception {
    String tenant_id = System.getenv().getOrDefault("TENANT_ID", TENANT_ID);
    DocumentMetadata context = new DocumentMetadata(tenant_id, "integrationTest", "sample",
        new HashMap<>(), "customRayID");
    int batchSize = 10000000;
    Map<String, DeterministicPlaintextField> batchData = getBatchMap(batchSize);

    DeterministicTenantSecurityClient client = createClient().get();
    BatchResult<DeterministicEncryptedField> encrypted =
        client.encryptBatch(batchData, context).get();
    assertEquals(encrypted.getSuccesses().size(), batchSize);
    assertEquals(encrypted.getFailures().size(), 0);

    BatchResult<DeterministicPlaintextField> decrypted =
        client.decryptBatch(encrypted.getSuccesses(), context).get();
    assertEquals(decrypted.getSuccesses().size(), batchSize);
    assertEquals(decrypted.getFailures().size(), 0);
    assertEqualBytes(decrypted.getSuccesses().get("0").getPlaintextField(),
        batchData.get("0").getPlaintextField());
    assertEqualBytes(decrypted.getSuccesses().get("9").getPlaintextField(),
        batchData.get("9").getPlaintextField());
  }

  public void batchRoundtripTestPartialFailure() throws Exception {
    String tenant_id = System.getenv().getOrDefault("TENANT_ID", TENANT_ID);
    DocumentMetadata context = new DocumentMetadata(tenant_id, "integrationTest", "sample",
        new HashMap<>(), "customRayID");
    Map<String, DeterministicPlaintextField> batchData = getBatchMap(2);

    DeterministicTenantSecurityClient client = createClient().get();
    BatchResult<DeterministicEncryptedField> encrypted =
        client.encryptBatch(batchData, context).get();
    assertEquals(encrypted.getSuccesses().size(), 2);
    assertEquals(encrypted.getFailures().size(), 0);

    HashMap<String, DeterministicEncryptedField> encryptedBatch = new HashMap<>();
    encryptedBatch.put("good", encrypted.getSuccesses().get("0"));

    DeterministicEncryptedField goodField = encrypted.getSuccesses().get("1");
    byte[] goodBytes = goodField.getEncryptedField();
    byte[] badBytes = Arrays.copyOfRange(goodBytes, 6, goodBytes.length);
    DeterministicEncryptedField badField = new DeterministicEncryptedField(badBytes,
        goodField.getDerivationPath(), goodField.getSecretPath());
    encryptedBatch.put("bad", badField);

    BatchResult<DeterministicPlaintextField> decrypted =
        client.decryptBatch(encryptedBatch, context).get();
    assertEquals(decrypted.getSuccesses().size(), 1);
    assertEquals(decrypted.getFailures().size(), 1);
    assertEqualBytes(decrypted.getSuccesses().get("good").getPlaintextField(),
        batchData.get("0").getPlaintextField());
    TenantSecurityException failure = decrypted.getFailures().get("bad");
    assertTrue(failure instanceof TenantSecurityException);
    assertEquals(failure.getErrorCode(),
        TenantSecurityErrorCodes.DETERMINISTIC_FIELD_DECRYPT_FAILED);
    assertTrue(failure.getCause() instanceof CompletionException);
    assertTrue(failure.getCause().getCause() instanceof CryptoException);
    assertEquals(failure.getCause().getCause().getMessage(), "Failed to parse field header.");
  }
}
