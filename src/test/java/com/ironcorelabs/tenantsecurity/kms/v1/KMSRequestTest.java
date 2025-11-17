package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import com.ironcorelabs.tenantsecurity.TestUtils;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import org.testng.annotations.Test;

@Test(groups = {"dev-integration"})
public class KMSRequestTest {
  private DocumentMetadata getMetadata() {
    Map<String, String> arbData = new HashMap<>();
    arbData.put("thingOne", "valuetwo");
    return new DocumentMetadata(NotPrimaryAndDisabledConfigs.MULTIPLE_TENANT_ID, "integrationTest",
        "sample", arbData);
  }

  private Map<String, byte[]> getDocument() {
    Map<String, byte[]> documentMap = new HashMap<>();
    try {
      documentMap.put("doc", "Fake data".getBytes("UTF-8"));
    } catch (Exception e) {
    }
    return documentMap;
  }

  public void errorCodeWhenServiceNotReachable() throws Exception {
    CompletableFuture<EncryptedDocument> encrypt =
        TenantSecurityClient.create("https://thisdomaindoesnotexist.eta", "apiKey")
            .thenCompose(client -> client.encrypt(getDocument(), getMetadata()));

    try {
      encrypt.get();
      fail("Request should fail when host is unreachable.");
    } catch (ExecutionException e) {
      assertTrue(e.getCause() instanceof TenantSecurityException);
      TenantSecurityException esError = (TenantSecurityException) e.getCause();
      assertNotNull(esError.getCause());
      assertEquals(esError.getErrorCode(), TenantSecurityErrorCodes.UNABLE_TO_MAKE_REQUEST);
    }
  }

  public void errorCodeWhenApiKeyIsWrong() throws Exception {
    CompletableFuture<EncryptedDocument> encrypt = TestUtils
        .createTscWithAllowInsecure(TestSettings.TSP_ADDRESS + TestSettings.TSP_PORT, "wrongKey")
        .thenCompose(client -> client.encrypt(getDocument(), getMetadata()));

    try {
      encrypt.get();
      fail("Request should fail when API key is wrong");
    } catch (ExecutionException e) {
      assertTrue(e.getCause() instanceof TenantSecurityException);
      TenantSecurityException esError = (TenantSecurityException) e.getCause();
      assertEquals(esError.getErrorCode(), TenantSecurityErrorCodes.UNAUTHORIZED_REQUEST);
    }
  }

  public void errorCodeWhenEdekFormatIsWrong() throws Exception {
    Map<String, byte[]> documentMap = new HashMap<>();
    documentMap.put("doc", new byte[] {3, 73, 82, 79, 78});
    EncryptedDocument eDoc = new EncryptedDocument(documentMap, "d2hhdCBhIHdhc3RlIG9mIHRpbWUK");

    CompletableFuture<PlaintextDocument> decrypt = TestUtils
        .createTscWithAllowInsecure(TestSettings.TSP_ADDRESS + TestSettings.TSP_PORT,
            NotPrimaryAndDisabledConfigs.INTEGRATION_API_KEY)
        .thenCompose(client -> client.decrypt(eDoc, getMetadata()));

    try {
      decrypt.get();
      fail("Request should fail when API key is wrong");
    } catch (ExecutionException e) {
      assertTrue(e.getCause() instanceof TenantSecurityException);
      TenantSecurityException esError = (TenantSecurityException) e.getCause();
      assertEquals(esError.getErrorCode(), TenantSecurityErrorCodes.INVALID_PROVIDED_EDEK);
    }
  }

}
