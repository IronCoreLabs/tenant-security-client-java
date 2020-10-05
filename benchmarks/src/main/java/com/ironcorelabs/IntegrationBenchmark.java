package com.ironcorelabs;

import java.lang.System;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import com.ironcorelabs.tenantsecurity.kms.v1.DocumentMetadata;
import com.ironcorelabs.tenantsecurity.kms.v1.PlaintextDocument;
import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityKMSClient;
import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityKMSErrorCodes;
import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityKMSException;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.infra.Blackhole;

@State(Scope.Thread)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class IntegrationBenchmark {
    // Default values that can be overridden by environment variables of the same name
    // These match up to the Demo TSP whose config we ship with the repo.
    private static String TSP_ADDRESS = "http://localhost";
    private static String TSP_PORT = "32804";
    private static String TENANT_ID = "tenant-gcp";
    private static String API_KEY = "0WUaXesNgbTAuLwn";

    private static final Map<String, String> customFields;
    static {
        Map<String, String> cfM = new HashMap<>();
        cfM.put("org_name", "Latifah");
        cfM.put("attachment_name", "ladies_first.mp3");
        customFields = Collections.unmodifiableMap(cfM);
    }
    private static DocumentMetadata context;
    private static final Map<String, byte[]> documentMap;
    static {
        Map<String, byte[]> dM = new HashMap<>();
        dM.put("doc1", "Encrypt these bytes!".getBytes(StandardCharsets.UTF_8));
        documentMap = Collections.unmodifiableMap(dM);
    }

    private static TenantSecurityKMSClient client;

    @Setup
    public void doSetup() {
        try {
            Map<String, String> envVars = System.getenv();
            String tsp_address = envVars.getOrDefault("TSP_ADDRESS", TSP_ADDRESS);
            String tsp_port = envVars.getOrDefault("TSP_PORT", TSP_PORT);
            String api_key = envVars.getOrDefault("API_KEY", API_KEY);
            String tenant_id = envVars.getOrDefault("TENANT_ID", TENANT_ID);
            context = new DocumentMetadata(tenant_id, "benchmark", "sample", customFields,
                    "customRayID");

            client = new TenantSecurityKMSClient(tsp_address + ":" + tsp_port, api_key);
        } catch (Exception e) {
        }
    }

    @TearDown
    public void doTearDown() {
        try {
            client.close();
        } catch (Exception e) {
        }
    }

    @Benchmark
    public void integrationRoundtrip(Blackhole blackhole) {
        try {
            CompletableFuture<PlaintextDocument> roundtrip =
                    client.encrypt(documentMap, context).thenCompose(encryptedResults -> {
                        return client.decrypt(encryptedResults, context);
                    });
            Map<String, byte[]> decryptedValuesMap = roundtrip.get().getDecryptedFields();
            blackhole.consume(decryptedValuesMap);
        } catch (Exception e) {
            if (e.getCause() instanceof TenantSecurityKMSException) {
                TenantSecurityKMSException kmsError = (TenantSecurityKMSException) e.getCause();
                TenantSecurityKMSErrorCodes errorCode = kmsError.getErrorCode();
                System.out.println("\nError Message: " + kmsError.getMessage());
                System.out.println("\nError Code: " + errorCode.getCode());
                System.out.println("\nError Code Info: " + errorCode.getMessage() + "\n");
            }
        }
    }
}
