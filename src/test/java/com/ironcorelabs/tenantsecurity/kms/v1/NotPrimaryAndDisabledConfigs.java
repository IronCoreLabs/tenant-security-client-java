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

@Test(groups = {"dev-integration"})
public class NotPrimaryAndDisabledConfigs {
    public static String MULTIPLE_TENANT_ID = "INTEGRATION-TEST-COMBO";
    protected static String INTEGRATION_API_KEY = System.getenv("API_KEY");

    /**
     * Data encrypted from a previous configuration. The configuration this data was encrypted to is
     * still active, but is not primary. We should be able to still decrypt this. This data was
     * encrypted via an AWS configuration.
     */
    private byte[] existingEncryptedDataForEnabledConfig = new byte[] {
        3,73,82,79,78,0,56,10,28,-48,-74,-114,-45,-58,-105,111,15,20,-110,86,-6,-86,109,36,-48,-115,-13,-127,
        -13,-86,77,31,118,-92,-54,16,-94,26,24,10,22,73,78,84,69,71,82,65,84,73,79,78,45,84,69,83,84,45,67,79,
        77,66,79,26,52,-85,-26,127,70,-1,-80,-97,101,-68,45,-66,-31,125,-66,32,-95,-11,113,-86,72,115,-24,-52,
        -114,-28,-112,123,83,16,30,107,-60,-16,-125,72,45,101,-30,100,39,126,-40};
    private String existingEdekForEnabledConfig =
            "Cr4BCrgBAQICAHhhfiI+R/CnS0NJxVMGLAbLb/uEr64mDJAXLrWWWxAMQgEE/9yB7Dit96VAM3c5UDCzAAAAfjB8BgkqhkiG9w0BBwagbzBtAgEAMGgGCSqGSIb3DQEHATAeBglghkgBZQMEAS4wEQQMquE2DnIIesdP/UknAgEQgDsHqfur2fJaAS8ZwnJNXr5cZWH1xL7xvIWgCzD9Aa1peULVadhDgUHXVUNTHodEr2JuUKXFGuX1aYMyehCaBA==";

    /**
     * Data encrypted from a previous configuration. The configuration this data was encrypted to
     * has been disabled. We should no longer be able to ask the Tenant Security Proxy to decrypt
     * this data. This data was encrypted via an Azure configuration.
     */
    private byte[] existingEncryptedDataForDisabledConfig = new byte[] {
        3,73,82,79,78,0,56,10,28,-83,13,21,-61,-47,-109,53,-78,-26,76,22,-111,-22,-21,-79,90,-118,107,-122,69,
        -111,126,42,75,-66,66,-10,-58,26,24,10,22,73,78,84,69,71,82,65,84,73,79,78,45,84,69,83,84,45,67,79,77,
        66,79,-66,77,-58,69,-61,57,110,-68,68,-6,-51,-95,118,93,-68,-74,71,-72,93,82,58,122,76,104,33,-52,-41,
        -95,-35,-43,56,-10,123,122,-108,5,71,71,-34,-64,50,-37,4,27};
    private String existingEdekForDisabledConfig =
            "CqsCCqUCCoACNPQp9pKbmS+QmQhUfsBE9HKkXMA+cREXiuDrgD/B/hI8zn7rU5Sk4a6trDSr7DoUsG3y6dtBpcoeVIMzgztVr0xo2jzmC1BkyS1CcopUDV7WOq+giZ6NMUTXCQV1fd4sX+yFYQPJrsJ7zHlL72QScxDb66qOjkYu+jLSXj77JHBbFMYPBLRL2rMzZLJ1UIvhmZ1kFpxg5UFQOvitOIT/qSwAZXrqP7yJ1WoFMPg9PypPbMErHLv/ScoNFpMFFbM/X2c/HJXMwL7XSE4uJMRQeXooJ/waXe9nZ1NP/VFQnt9waMn0jYAdnQEbZOd6qp/Ib0HUDyAu2G0ymTGJmooBCRIgOWY5NWZkMjk0NjRhNDA0YzhjNzI1N2U3Njc5Y2MyZWYQoAQ=";

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
        return new DocumentMetadata(NotPrimaryAndDisabledConfigs.MULTIPLE_TENANT_ID,
                "integrationTest", "sample", arbData);
    }

    public void decryptActiveConfigData() throws Exception {
        Map<String, byte[]> document = new HashMap<>();
        document.put("doc", "I'm Gumby dammit".getBytes("UTF-8"));
        CompletableFuture<PlaintextDocument> decrypted = getClient().thenCompose(
                client -> client.decrypt(this.getExistingEncryptedDataForEnabledConfig(),
                        this.getRoundtripMetadata()));
        Map<String, byte[]> decryptedValuesMap = decrypted.get().getDecryptedFields();
        assertEqualBytes(decryptedValuesMap.get("doc"), "I'm Gumby dammit".getBytes("UTF-8"));
    }

    @Test
    public void failToEncryptNewData() throws Exception {
        DocumentMetadata metadata = getRoundtripMetadata();
        Map<String, byte[]> documentMap = new HashMap<>();
        documentMap.put("doc", "I'm Gumby dammit".getBytes("UTF-8"));
        CompletableFuture<EncryptedDocument> encrypt =
                getClient().thenCompose(client -> client.encrypt(documentMap, metadata));
        try {
            encrypt.get();
            fail("Request should fail to encrypt new data");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TenantSecurityException);
            TenantSecurityException esError = (TenantSecurityException) e.getCause();
            assertEquals(esError.getErrorCode(),
                    TenantSecurityErrorCodes.NO_PRIMARY_KMS_CONFIGURATION);
        }
    }

    @Test
    public void failToDecryptDataFromDisabledConfig() throws Exception {
        CompletableFuture<PlaintextDocument> decrypted = getClient().thenCompose(
                client -> client.decrypt(this.getExistingEncryptedDataForDisabledConfig(),
                        this.getRoundtripMetadata()));

        try {
            decrypted.get();
            fail("Request should fail to decrypt data when config is missing");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TenantSecurityException);
            TenantSecurityException esError = (TenantSecurityException) e.getCause();
            assertEquals(esError.getErrorCode(),
                    TenantSecurityErrorCodes.KMS_CONFIGURATION_DISABLED);
        }
    }

    @Test
    public void failToDecryptDataFromUnknownTenant() throws Exception {
        CompletableFuture<PlaintextDocument> decrypted = getClient().thenCompose(
                client -> client.decrypt(this.getExistingEncryptedDataForDisabledConfig(),
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
