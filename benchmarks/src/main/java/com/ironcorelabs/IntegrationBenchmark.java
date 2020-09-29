package com.ironcorelabs;

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
    private static String TSP_ADDRESS = "http://localhost";
    private static String TSP_PORT = ":7777";
    private static String TENANT_ID = "";
    private static String API_KEY = "";
    private static final Map<String, String> customFields;
    static {
        Map<String, String> cfM = new HashMap<>();
        cfM.put("org_name", "Latifah");
        cfM.put("attachment_name", "ladies_first.mp3");
        customFields = Collections.unmodifiableMap(cfM);
    }
    private static final DocumentMetadata context =
            new DocumentMetadata(TENANT_ID, "benchmark", "sample", customFields, "customRayID");
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
            client = new TenantSecurityKMSClient(TSP_ADDRESS + TSP_PORT, API_KEY);
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
