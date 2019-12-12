package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import org.testng.annotations.Test;

@Test(groups = { "local-batch-integration" })
public class LocalBatch {
    private String TENANT_ID = "DKDNG-ET-EN93J";
    private String API_KEY = "IF7RlyMTXO3dTP5s";

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

    private List<Map<String, byte[]>> getBatch(int batchSize) {
        return Arrays.stream(new int[batchSize]).mapToObj(_nope -> getRoundtripDataToEncrypt())
                .collect(Collectors.toList());
    }

    public void gcpRoundtripTest() throws Exception {
        DocumentMetadata context = new DocumentMetadata(this.TENANT_ID, "integrationTest", "sample");

        TenantSecurityKMSClient client = new TenantSecurityKMSClient("http://localhost:7777", this.API_KEY);

        int batchSize = 25;
        int batchRepetitions = 50;

        CompletableFuture<List<PlaintextDocument>> roundtrip = client.encryptBatch(getBatch(batchSize), context)
                .thenCompose(encryptedResults -> {
                    System.out.println("Run 1");
                    return client.decryptBatch(encryptedResults, context);
                });

        for (int i = 2; i <= batchRepetitions; i++) {
            final String run = "Run " + i;
            roundtrip = roundtrip.thenCompose(_nope -> client.encryptBatch(getBatch(batchSize), context))
                    .thenCompose(encryptedResults -> {
                        System.out.println(run);
                        return client.decryptBatch(encryptedResults, context);
                    });

        }

        try {
            roundtrip.get();
        } catch (ExecutionException e) {
            System.out.println(e.getCause());
            if (e.getCause() instanceof TenantSecurityKMSException) {
                TenantSecurityKMSException kmsError = (TenantSecurityKMSException) e.getCause();
                TenantSecurityKMSErrorCodes errorCode = kmsError.getErrorCode();
                System.out.println("\nError Code: " + errorCode.getCode());
                System.out.println("\nError Code Info: " + errorCode.getMessage());
            }
            throw e;
        }
    }
}