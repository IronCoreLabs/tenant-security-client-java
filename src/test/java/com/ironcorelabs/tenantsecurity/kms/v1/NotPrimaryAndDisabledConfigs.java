package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.testng.annotations.Test;

@Test(groups = { "dev-integration" })
public class NotPrimaryAndDisabledConfigs {
    public static String MULTIPLE_TENANT_ID = "INTEGRATION-TEST-DEV1-COMBO";
    public static String INTEGRATION_API_KEY = "qlhqGW+Azctfy1ld";

    /**
     * Data encrypted from a previous configuration. The configuration this data was
     * encrypted to is still active, but is not primary. We should be able to still
     * decrypt this. This data was encrypted via an AWS configuration.
     */
    private byte[] existingEncryptedDataForEnabledConfig = new byte[] { 3, 73, 82, 79, 78, 0, 0, 85, -104, 85, -101,
            -61, 2, 66, 122, 89, -118, 55, 101, -89, 79, -5, 115, 82, 77, 0, 55, 29, -14, -48, -59, 11, 63, -126, -62,
            107, -85, 88, -45, -89, 88, 19, 6, -50, 112, -101 };
    private String existingEdekForEnabledConfig = "Cr4BCrgBAQIDAHj0ZREHq1bONJuR5ImNOlC8TTbXrFSZ5ETcue/j52IG8AFHigXyTIDryqdkPfVVMC2yAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMGTmWho89vfNOIdymAgEQgDvJnGyaDKgcFGNz3s+TPpZl0eVOYu9Ex4Ym0J7xXO8hlx0QSgvzp+AppxbxHIzTN/weT5fibfSw3yZybRDvAw==";

    /**
     * Data encrypted from a previous configuration. The configuration this data was
     * encrypted to has been disabled. We should no longer be able to ask the Tenant
     * Security Proxy to decrypt this data. This data was encrypted via an Azure
     * configuration.
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

    private CompletableFuture<TenantSecurityKMSClient> getClient() {
        return TenantSecurityKMSClient.create("http://localhost:7777",
                NotPrimaryAndDisabledConfigs.INTEGRATION_API_KEY);
    }

    private DocumentMetadata getRoundtripMetadata() {
        Map<String, String> arbData = new HashMap<>();
        arbData.put("thingOne", "valuetwo");
        return new DocumentMetadata(NotPrimaryAndDisabledConfigs.MULTIPLE_TENANT_ID, "integrationTest", "sample",
                arbData);
    }

    public void decryptActiveConfigData() throws Exception {
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
            assertTrue(e.getCause() instanceof TenantSecurityKMSException);
            TenantSecurityKMSException esError = (TenantSecurityKMSException) e.getCause();
            assertEquals(esError.getErrorCode(), TenantSecurityKMSErrorCodes.NO_PRIMARY_KMS_CONFIGURATION);
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
            assertTrue(e.getCause() instanceof TenantSecurityKMSException);
            TenantSecurityKMSException esError = (TenantSecurityKMSException) e.getCause();
            assertEquals(esError.getErrorCode(), TenantSecurityKMSErrorCodes.KMS_CONFIGURATION_DISABLED);
        }
    }

    @Test
    public void failToDecryptDataFromUnknownTenant() throws Exception {
        CompletableFuture<PlaintextDocument> decrypted = getClient()
                .thenCompose(client -> client.decrypt(this.getExistingEncryptedDataForDisabledConfig(),
                        new DocumentMetadata("unknownTenant", "integrationTest", "sample")));

        try {
            decrypted.get();
            fail("Request should fail to decrypt data when provided tenant doesnt exist");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TenantSecurityKMSException);
            TenantSecurityKMSException esError = (TenantSecurityKMSException) e.getCause();
            assertEquals(esError.getErrorCode(),
                    TenantSecurityKMSErrorCodes.UNKNOWN_TENANT_OR_NO_ACTIVE_KMS_CONFIGURATIONS);
        }
    }
}