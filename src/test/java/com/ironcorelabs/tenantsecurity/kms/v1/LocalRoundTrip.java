package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.logdriver.v1.EventMetadata;
import com.ironcorelabs.tenantsecurity.logdriver.v1.UserEvent;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

@Test(groups = {"local-integration"})
public class LocalRoundTrip {
    // Default values that can be overridden by environment variables of the same name
    // These match up to the Demo TSP whose config we ship with the repo.
    private static String TENANT_ID = "tenant-gcp";
    private static String API_KEY = "0WUaXesNgbTAuLwn";

    private void assertEqualBytes(byte[] one, byte[] two) throws Exception {
        assertEquals(new String(one, "UTF-8"), new String(two, "UTF-8"));
    }

    private Map<String, byte[]> getRoundtripDataToEncrypt() throws Exception {
        Map<String, byte[]> documentMap = new HashMap<>();
        documentMap.put("doc1", "Encrypt these bytes!".getBytes("UTF-8"));
        documentMap.put("doc2", "And these bytes!".getBytes("UTF-8"));
        documentMap.put("doc3", "And my axe!".getBytes("UTF-8"));
        return documentMap;
    }

    public void roundtripTest() throws Exception {
        Map<String, String> customFields = new HashMap<>();
        customFields.put("org_name", "Cisco");
        customFields.put("attachment_name", "thongsong.mp3");

        Map<String, String> envVars = System.getenv();
        String tsp_address = envVars.getOrDefault("TSP_ADDRESS", TestSettings.TSP_ADDRESS);
        String tsp_port = envVars.getOrDefault("TSP_PORT", TestSettings.TSP_PORT);
        String api_key = envVars.getOrDefault("API_KEY", API_KEY);
        String tenant_id = envVars.getOrDefault("TENANT_ID", TENANT_ID);

        if (tsp_port.charAt(0) != ':') {
            tsp_port = ":" + tsp_port;
        }

        DocumentMetadata context = new DocumentMetadata(tenant_id, "integrationTest", "sample", customFields, "customRayID");
        Map<String, byte[]> documentMap = getRoundtripDataToEncrypt();

        CompletableFuture<PlaintextDocument> roundtrip = TenantSecurityClient
                .create(tsp_address + tsp_port, api_key).thenCompose(client -> {

                    try {
                        return client.encrypt(documentMap, context)
                                .thenCompose(encryptedResults -> {
                                    System.out.println(encryptedResults.getEdek());
                                    Map<String, byte[]> fields =
                                            encryptedResults.getEncryptedFields();
                                    System.out.println(Arrays.toString(fields.get("doc1")));
                                    System.out.println(Arrays.toString(fields.get("doc2")));
                                    System.out.println(Arrays.toString(fields.get("doc3")));
                                    return client.decrypt(encryptedResults, context);
                                });
                    } catch (Exception e) {
                        throw new CompletionException(e);
                    }
                });

        try {
            Map<String, byte[]> decryptedValuesMap = roundtrip.get().getDecryptedFields();
            assertEqualBytes(decryptedValuesMap.get("doc1"), documentMap.get("doc1"));
            assertEqualBytes(decryptedValuesMap.get("doc2"), documentMap.get("doc2"));
            assertEqualBytes(decryptedValuesMap.get("doc3"), documentMap.get("doc3"));
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

    public void logSecurityEventBadTenant() throws Exception {

        Map<String, String> envVars = System.getenv();
        String tsp_address = envVars.getOrDefault("TSP_ADDRESS", TestSettings.TSP_ADDRESS);
        String tsp_port = envVars.getOrDefault("TSP_PORT", TestSettings.TSP_PORT);
        String api_key = envVars.getOrDefault("API_KEY", API_KEY);
        String tenant_id = "bad-tenant-id";

        if (tsp_port.charAt(0) != ':') {
            tsp_port = ":" + tsp_port;
        }

        EventMetadata metadata = new EventMetadata(tenant_id, "integrationTest", "sample", "app-request-id");

        // even though this tenant is bad, the response here will be success as the security
        // event was enqueued for further processing.
        CompletableFuture<Void> logEvent = TenantSecurityClient
                .create(tsp_address + tsp_port, api_key).thenCompose(client -> {
                    return client.logSecurityEvent(UserEvent.ADD, metadata);
                });

        try {
            logEvent.get();
        } catch (Exception e) {
            fail("Security Event logging should not fail");
        }
    }
}
