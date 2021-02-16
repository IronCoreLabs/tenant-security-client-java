package com.ironcorelabs.logging;

import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;
import com.ironcorelabs.tenantsecurity.kms.v1.*;
import com.ironcorelabs.tenantsecurity.logdriver.v1.*;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.*;

public class LoggingExample {
  public static void main(String[] args) throws Exception {
    // In order to communicate with the TSP, you need a matching API_KEY. Find the
    // right value from end of the TSP configuration file, and set the API_KEY
    // environment variable to that value.
    String API_KEY = System.getenv("API_KEY");
    if (API_KEY == null) {
      System.out.println("Must set the API_KEY environment variable.");
      System.exit(1);
    }

    // For this example, make sure you use a tenant that has security event logging
    // enabled so you can actually see the events logged to the appropriate SIEM.
    String TENANT_ID = System.getenv("TENANT_ID");
    if (TENANT_ID == null) {
      TENANT_ID = "tenant-gcp-l";
    }
    System.out.println("Using tenant " + TENANT_ID);

    // Initialize the client with a Tenant Security Proxy domain and API key.
    // Typically this would be done once when the application or service initializes
    TenantSecurityClient client = TenantSecurityClient.create("http://localhost:32804", API_KEY).get();

    //
    // Example 1: logging a user-related event
    //
    // Create metadata about the event. This example populates all possible fields
    // with a value, including the
    // otherData map. Sets the timestamp to 5 seconds before the current data/time.
    Map<String, String> otherData = new HashMap<>();
    otherData.put("field1", "gumby");
    otherData.put("field2", "gumby");
    EventMetadata metadata1 = new EventMetadata(TENANT_ID, "userId1", "PII", otherData, "Rq8675309", "127.0.0.1",
        "userId1", System.currentTimeMillis());
    try {
      client.logSecurityEvent(UserEvent.LOGIN, metadata1).get();
      System.out.println("Successfully logged user login event.");
    } catch (ExecutionException e) {
      if (e.getCause() instanceof TenantSecurityException) {
        System.out.println("Error logging user login event:");
        TenantSecurityException error = (TenantSecurityException) e.getCause();
        TenantSecurityErrorCodes errorCode = error.getErrorCode();
        System.out.println("\nError Message: " + error.getMessage());
        System.out.println("\nError Code: " + errorCode.getCode());
        System.out.println("\nError Code Info: " + errorCode.getMessage() + "\n");
      }
      throw e;
    }

    //
    // Example 2: logging an admin-related event
    //
    // This one adds minimal metadata for the event. The timestamp should be roughly
    // 5 seconds after the one on the previous event.
    EventMetadata metadata2 = new EventMetadata(TENANT_ID, "adminId1", "PII");
    try {
      client.logSecurityEvent(UserEvent.ADD, metadata2).get();
      System.out.println("Successfully logged admin add event.");
    } catch (ExecutionException e) {
      if (e.getCause() instanceof TenantSecurityException) {
        System.out.println("Error logging admin add event:");
        TenantSecurityException error = (TenantSecurityException) e.getCause();
        TenantSecurityErrorCodes errorCode = error.getErrorCode();
        System.out.println("\nError Message: " + error.getMessage());
        System.out.println("\nError Code: " + errorCode.getCode());
        System.out.println("\nError Code Info: " + errorCode.getMessage() + "\n");
      }
      throw e;
    }

    // You should be able to see that these two events were delivered in the TSP
    // logs. If you have access to the example tenant's SIEM, you can see these
    // events in their logs.

    System.exit(0);
  };
}
