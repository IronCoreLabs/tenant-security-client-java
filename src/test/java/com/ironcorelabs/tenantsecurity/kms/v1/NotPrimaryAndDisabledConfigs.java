package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import org.testng.annotations.Test;

@Test(groups = { "dev-integration" })
public class NotPrimaryAndDisabledConfigs {
    public static String MULTIPLE_TENANT_ID = "INTEGRATION-TEST-DEV1-COMBO";
    public static String INTEGRATION_API_KEY = "qlhqGW+Azctfy1ld";

    /**
     * Data encrypted from a previous configuration. The configuration this data was encrypted to is
     * still active, but is not primary. We should be able to still decrypt this. This data was
     * encrypted via an AWS configuration.
     */
    private byte[] existingEncryptedDataForEnabledConfig = new byte[] { 3, 73, 82, 79, 78, 0, 0, 52, 97, 69, -17, -65,
            32, 85, -70, 101, 109, -67, 31, -28, -38, -19, -78, 42, 125, 124, -47, 80, 31, 10, 127, -109, -20, 90, 7,
            88, 104, 103, -64, -56, 38, 95, 96, -97, -92, -54 };
    private String existingEdekForEnabledConfig = "Cr4BCrgBAQICAHhhfiI+R/CnS0NJxVMGLAbLb/uEr64mDJAXLrWWWxAMQgF/DRnb5dvopCbObDSBn/dtAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMxp38R1TYd/u4Ie2oAgEQgDuY9+X/BNebcFdZYV2SC7w723+W2a4QAgFqMAI0W7QKHI2EbZF7d63PNWUoaeXX3Zk3W42q2OPShRAiTRCCBA==";

    /**
     * Data encrypted from a previous configuration. The configuration this data was encrypted to
     * has been disabled. We should no longer be able to ask the Tenant Security Proxy to decrypt
     * this data. This data was encrypted via an Azure configuration.
     */
    private byte[] existingEncryptedDataForDisabledConfig = new byte[] { 3, 73, 82, 79, 78, 0, 0, -77, 108, 93, -13,
            -20, -69, 116, -17, -41, 107, 49, 56, -8, 109, 105, 107, -108, 4, 2, -50, 21, -127, -124, 69, 34, 78, 84,
            56, 101, -98, 126, -79, 46, 65, 91, 95, 66, -111, 8 };
    private String existingEdekForDisabledConfig = "CoYCCoACi6JH7ZOggHm0fyIsUc4jVvK0jgPfn1V76xfVxYfBLP7QbfeZD7Gyzj4Xxdj4upJ7grzjCe8ydK3Q6ijeBOt7b050BhUHRsHUgdV7zBGWvaZOhPQ4sYl5bFVcefyQyk7EeN/qd6RGYq9AHEcBTzgx+Nw83Jgr34SPHSbTkhUIIJTzt0NAwJsQ7ZYMv2NHQ1LdjItr8/mJsu9i5R6yd3p2fuKWJozeAPHp9Salc9Vr5uwfGZsAKHNkbDlYvXFs6bO7TV2T2fOmevln2Yi/UEq6RqFa2FmzJMqVxeAbMNpCJ0KlcjqsI4cOD4VjotiXu4umTsMCIkN7I5KCZHKG3Bo+1xDwAw==";

    private EncryptedDocument getExistingEncryptedDataForEnabledConfig() {
        Map<String, byte[]> documentMap = new HashMap<>();
        documentMap.put("doc", this.existingEncryptedDataForEnabledConfig);
        return new EncryptedDocument(documentMap, this.existingEdekForEnabledConfig);
    }

    private EncryptedDocument getExistingEncryptedDataForDisabledConfig() {
        Map<String, byte[]> documentMap = new HashMap<>();
        documentMap.put("doc", this.existingEncryptedDataForDisabledConfig);
        return new EncryptedDocument(documentMap, this.existingEdekForDisabledConfig);
    }

    private void assertEqualBytes(byte[] one, byte[] two) throws Exception {
        assertEquals(new String(one, "UTF-8"), new String(two, "UTF-8"));
    }

    private CompletableFuture<TenantSecurityClient> getClient() {
        return TenantSecurityClient.create(TestSettings.TSP_ADDRESS + TestSettings.TSP_PORT,
                NotPrimaryAndDisabledConfigs.INTEGRATION_API_KEY);
    }

    private DocumentMetadata getRoundtripMetadata() {
        Map<String, String> arbData = new HashMap<>();
        arbData.put("thingOne", "valuetwo");
        return new DocumentMetadata(NotPrimaryAndDisabledConfigs.MULTIPLE_TENANT_ID, "integrationTest", "sample",
                arbData);
    }

    public void decryptActiveConfigData() throws Exception {
        Map<String, byte[]> document = new HashMap<>();
        document.put("doc", "Wont happen".getBytes("UTF-8"));
        CompletableFuture<PlaintextDocument> decrypted = getClient().thenCompose(
                client -> client.decrypt(this.getExistingEncryptedDataForEnabledConfig(), this.getRoundtripMetadata()));
        Map<String, byte[]> decryptedValuesMap = decrypted.get().getDecryptedFields();
        assertEqualBytes(decryptedValuesMap.get("doc"), "Wont happen".getBytes("UTF-8"));
    }

    @Test
    public void failToEncryptNewData() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata();
        Map<String, byte[]> documentMap = new HashMap<>();
        documentMap.put("doc", "Wont happen".getBytes("UTF-8"));
        CompletableFuture<EncryptedDocument> encrypt = getClient()
                .thenCompose(client -> client.encrypt(documentMap, metadata));
        try {
            encrypt.get();
            fail("Request should fail to encrypt new data");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TenantSecurityException);
            TenantSecurityException esError = (TenantSecurityException) e.getCause();
            assertEquals(esError.getErrorCode(), TenantSecurityErrorCodes.NO_PRIMARY_KMS_CONFIGURATION);
        }
    }

    @Test
    public void failToDecryptDataFromDisabledConfig() throws Exception {
        CompletableFuture<PlaintextDocument> decrypted = getClient().thenCompose(client -> client
                .decrypt(this.getExistingEncryptedDataForDisabledConfig(), this.getRoundtripMetadata()));

        try {
            decrypted.get();
            fail("Request should fail to decrypt data when config is missing");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TenantSecurityException);
            TenantSecurityException esError = (TenantSecurityException) e.getCause();
            assertEquals(esError.getErrorCode(), TenantSecurityErrorCodes.KMS_CONFIGURATION_DISABLED);
        }
    }

    @Test
    public void failToDecryptDataFromUnknownTenant() throws Exception {
        CompletableFuture<PlaintextDocument> decrypted = getClient()
                .thenCompose(client -> client.decrypt(this.getExistingEncryptedDataForDisabledConfig(),
                        new DocumentMetadata("unknownTenant", "integrationTest", "sample")));

        try {
            decrypted.get();
            fail("Request should fail to decrypt data when provided tenant doesn't exist");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TenantSecurityException);
            TenantSecurityException esError = (TenantSecurityException) e.getCause();
            assertEquals(esError.getErrorCode(),
                    TenantSecurityErrorCodes.UNKNOWN_TENANT_OR_NO_ACTIVE_KMS_CONFIGURATIONS);
        }
    }
}
