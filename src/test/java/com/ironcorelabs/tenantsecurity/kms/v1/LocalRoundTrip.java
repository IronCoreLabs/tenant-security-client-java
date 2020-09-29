package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import org.testng.annotations.Test;

@Test(groups = {"local-integration"})
public class LocalRoundTrip {
    private String TENANT_ID = "";
    private String API_KEY = "";

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
        DocumentMetadata context = new DocumentMetadata(this.TENANT_ID, "integrationTest", "sample",
                customFields, "customRayID");
        Map<String, byte[]> documentMap = getRoundtripDataToEncrypt();

        CompletableFuture<PlaintextDocument> roundtrip = TenantSecurityKMSClient
                .create(TestSettings.TSP_ADDRESS + TestSettings.TSP_PORT, this.API_KEY)
                .thenCompose(client -> {

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
            if (e.getCause() instanceof TenantSecurityKMSException) {
                TenantSecurityKMSException kmsError = (TenantSecurityKMSException) e.getCause();
                TenantSecurityKMSErrorCodes errorCode = kmsError.getErrorCode();
                System.out.println("\nError Message: " + kmsError.getMessage());
                System.out.println("\nError Code: " + errorCode.getCode());
                System.out.println("\nError Code Info: " + errorCode.getMessage() + "\n");
            }
            throw e;
        }

    }
}
