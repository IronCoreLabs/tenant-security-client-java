package com.ironcorelabs;

import java.lang.System;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.Random;

import com.ironcorelabs.tenantsecurity.kms.v1.DocumentMetadata;
import com.ironcorelabs.tenantsecurity.kms.v1.EncryptedDocument;
import com.ironcorelabs.tenantsecurity.kms.v1.PlaintextDocument;
import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityClient;
import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityErrorCodes;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.kms.v1.BatchResult;

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
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class IntegrationBenchmark {
  // Default values that can be overridden by environment variables of the same name
  // These match up to the Demo TSP whose config we ship with the repo.
  private static String TSP_ADDRESS = "http://localhost";
  private static String TSP_PORT = "32804";
  private static String TENANT_ID = "tenant-gcp";
  private static String API_KEY = "0WUaXesNgbTAuLwn";
  private static DocumentMetadata metadata;

  private static Map<String, byte[]> smallDocumentMap;
  private static Map<String, byte[]> mediumDocumentMap;
  private static Map<String, byte[]> largeDocumentMap;
  private static Map<String, byte[]> extraLargeDocumentMap;
  private static EncryptedDocument smallEncryptedDocument;
  private static EncryptedDocument mediumEncryptedDocument;
  private static EncryptedDocument largeEncryptedDocument;
  private static EncryptedDocument extraLargeEncryptedDocument;
  private static Map<String, Map<String, byte[]>> batchPlaintexts;

  private static TenantSecurityClient client;

  private Map<String, byte[]> generatePlaintextDocument(int bytesPerField, int numFields) {
    Map<String, byte[]> documentMap = new HashMap<>();
    for (int i = 0; i < numFields; i++) {
      byte[] byteArray = new byte[bytesPerField];
      new Random().nextBytes(byteArray);
      documentMap.put("field" + i, byteArray);

    }
    return Collections.unmodifiableMap(documentMap);
  }

  @Setup
  public void doSetup() {
    try {

      Map<String, String> envVars = System.getenv();
      String tsp_address = envVars.getOrDefault("TSP_ADDRESS", TSP_ADDRESS);
      String tsp_port = envVars.getOrDefault("TSP_PORT", TSP_PORT);
      String api_key = envVars.getOrDefault("API_KEY", API_KEY);
      String tenant_id = envVars.getOrDefault("TENANT_ID", TENANT_ID);
      metadata =
          new DocumentMetadata(tenant_id, "benchmark", "sample", new HashMap(), "customRayID");
      client = new TenantSecurityClient(tsp_address + ":" + tsp_port, api_key);
      smallDocumentMap = generatePlaintextDocument(1, 1);
      mediumDocumentMap = generatePlaintextDocument(100, 1);
      largeDocumentMap = generatePlaintextDocument(10_000, 1);
      extraLargeDocumentMap = generatePlaintextDocument(1_000_000, 1);

      int numDocuments = 10;
      int numFields = 10;
      int fieldSize = 10;
      Map<String, Map<String, byte[]>> newBatchPlaintexts = new HashMap<>();
      for (int i = 0; i < numDocuments; i++) {
        newBatchPlaintexts.put("doc" + i, generatePlaintextDocument(fieldSize, numFields));
      }
      batchPlaintexts = newBatchPlaintexts;

      smallEncryptedDocument = client.encrypt(smallDocumentMap, metadata).get();
      mediumEncryptedDocument = client.encrypt(mediumDocumentMap, metadata).get();
      largeEncryptedDocument = client.encrypt(largeDocumentMap, metadata).get();
      extraLargeEncryptedDocument = client.encrypt(extraLargeDocumentMap, metadata).get();
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

  public void benchmarkEncrypt(Blackhole blackhole, Map<String, byte[]> documentMap) {
    try {
      CompletableFuture<EncryptedDocument> encrypted = client.encrypt(documentMap, metadata);
      Map<String, byte[]> encryptedValuesMap = encrypted.get().getEncryptedFields();
      blackhole.consume(encryptedValuesMap);
    } catch (Exception e) {
      if (e.getCause() instanceof TenantSecurityException) {
        TenantSecurityException kmsError = (TenantSecurityException) e.getCause();
        TenantSecurityErrorCodes errorCode = kmsError.getErrorCode();
        System.out.println("\nError Message: " + kmsError.getMessage());
        System.out.println("\nError Code: " + errorCode.getCode());
        System.out.println("\nError Code Info: " + errorCode.getMessage() + "\n");
      }
    }
  }

  public void benchmarkDecrypt(Blackhole blackhole, EncryptedDocument document) {
    try {
      CompletableFuture<PlaintextDocument> decrypted = client.decrypt(document, metadata);
      Map<String, byte[]> decryptedValuesMap = decrypted.get().getDecryptedFields();
      blackhole.consume(decryptedValuesMap);
    } catch (Exception e) {
      if (e.getCause() instanceof TenantSecurityException) {
        TenantSecurityException kmsError = (TenantSecurityException) e.getCause();
        TenantSecurityErrorCodes errorCode = kmsError.getErrorCode();
        System.out.println("\nError Message: " + kmsError.getMessage());
        System.out.println("\nError Code: " + errorCode.getCode());
        System.out.println("\nError Code Info: " + errorCode.getMessage() + "\n");
      }
    }
  }

  @Benchmark
  public void encrypt1B(Blackhole blackhole) {
    benchmarkEncrypt(blackhole, smallDocumentMap);
  }

  @Benchmark
  public void encrypt100B(Blackhole blackhole) {
    benchmarkEncrypt(blackhole, mediumDocumentMap);
  }

  @Benchmark
  public void encrypt10KB(Blackhole blackhole) {
    benchmarkEncrypt(blackhole, largeDocumentMap);
  }

  @Benchmark
  public void encrypt1MB(Blackhole blackhole) {
    benchmarkEncrypt(blackhole, extraLargeDocumentMap);
  }

  @Benchmark
  public void decrypt1B(Blackhole blackhole) {
    benchmarkDecrypt(blackhole, smallEncryptedDocument);
  }

  @Benchmark
  public void decrypt100B(Blackhole blackhole) {
    benchmarkDecrypt(blackhole, mediumEncryptedDocument);
  }

  @Benchmark
  public void decrypt10KB(Blackhole blackhole) {
    benchmarkDecrypt(blackhole, largeEncryptedDocument);
  }

  @Benchmark
  public void decrypt1MB(Blackhole blackhole) {
    benchmarkDecrypt(blackhole, extraLargeEncryptedDocument);
  }

  // 10 docs, 10 fields in each doc, 10 bytes in each field
  @Benchmark
  public void batchEncrypt10DocsOf100B(Blackhole blackhole) {
    try {
      CompletableFuture<BatchResult<EncryptedDocument>> encrypted =
          client.encryptBatch(batchPlaintexts, metadata);
      BatchResult<EncryptedDocument> encryptedSuccesses = encrypted.get();
      blackhole.consume(encryptedSuccesses);
    } catch (Exception e) {
      if (e.getCause() instanceof TenantSecurityException) {
        TenantSecurityException kmsError = (TenantSecurityException) e.getCause();
        TenantSecurityErrorCodes errorCode = kmsError.getErrorCode();
        System.out.println("\nError Message: " + kmsError.getMessage());
        System.out.println("\nError Code: " + errorCode.getCode());
        System.out.println("\nError Code Info: " + errorCode.getMessage() + "\n");
      }
    }

  }
}
