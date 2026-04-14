package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import com.ironcorelabs.tenantsecurity.TestUtils;
import org.testng.annotations.Test;

/**
 * Integration test that decrypts V3-format documents produced by ironcore-alloy in legacy mode.
 * This confirms that the TSC Java library can decrypt documents written by ironcore-alloy's
 * legacy_tsc_write_format option.
 *
 * The hardcoded EDEK and encrypted field fixtures come from
 * ironcore-alloy/tests/legacy_format.rs and were encrypted with tenant-gcp-l.
 */
@Test(groups = {"local-integration"})
public class LegacyFormatDecryptTest {
  private static final String TENANT_ID = "tenant-gcp-l";
  private static final String API_KEY = "0WUaXesNgbTAuLwn";

  // V3 EDEK from ironcore-alloy legacy format fixtures
  private static final String V3_EDEK =
      "CsABCjBouxrw3TFZtSO6cgPOM15ewNFH8uqIU+ordPNLK/M7vS7qihZlJVJNMnEQevFeQ18Q/wMYqg0iDKj2tv0ToheETqmBeyp4CnYKcQokAKUEZIf9Qdt+hRqFMjVQKP0EHlmWMGeU6tQs0bzmrl69vWE4EkkA3PhOjPCtLSjyH9Ds02CuqKTAl6tgBxadfFeWp9JMY059IZN6Gj+qfjT2vPdtWQR0NAhFPN3Ex1FXpqX+NNTcz59jll+2c0eLEP8D";

  // V3 encrypted field bytes from ironcore-alloy legacy format fixtures
  private static final String V3_ENCRYPTED_FIELD =
      "A0lST04ALgoc0x0jEo+VjaJpWEgrC2u//30unDURXl37Y2UbYBoOCgx0ZW5hbnQtZ2NwLWyzvlmZt+wuFmRVkkCBONrqkr9kAC/iRF+Mp8i5uRyj";

  private static final byte[] EXPECTED_PLAINTEXT = new byte[] {1, 2, 3};

  private CompletableFuture<TenantSecurityClient> getClient() {
    Map<String, String> envVars = System.getenv();
    String tspAddress = envVars.getOrDefault("TSP_ADDRESS", TestSettings.TSP_ADDRESS);
    String tspPort =
        TestUtils.ensureLeadingColon(envVars.getOrDefault("TSP_PORT", TestSettings.TSP_PORT));
    String apiKey = envVars.getOrDefault("API_KEY", API_KEY);
    return TestUtils.createTscWithAllowInsecure(tspAddress + tspPort, apiKey);
  }

  public void decryptV3LegacyFormatFromAlloy() throws Exception {
    Map<String, String> envVars = System.getenv();
    String tenantId = envVars.getOrDefault("TENANT_ID", TENANT_ID);
    DocumentMetadata metadata = new DocumentMetadata(tenantId, "legacyFormatTest", "integration");

    byte[] encryptedFieldBytes = Base64.getDecoder().decode(V3_ENCRYPTED_FIELD);
    Map<String, byte[]> encryptedFields = new HashMap<>();
    encryptedFields.put("field", encryptedFieldBytes);

    EncryptedDocument encryptedDoc = new EncryptedDocument(encryptedFields, V3_EDEK);

    PlaintextDocument result = getClient()
        .thenCompose(client -> client.decrypt(encryptedDoc, metadata)).get();

    assertEquals(result.getDecryptedFields().get("field"), EXPECTED_PLAINTEXT);
  }
}
