package com.ironcorelabs.tenantsecurity;

import java.util.concurrent.CompletableFuture;
import com.ironcorelabs.tenantsecurity.kms.v1.TenantSecurityClient;
import com.ironcorelabs.tenantsecurity.utils.CompletableFutures;

public class TestUtils {
  public static CompletableFuture<TenantSecurityClient> createTscWithAllowInsecure(
      String tspAddress, String apiKey) {
    return CompletableFutures.tryCatchNonFatal(
        () -> new TenantSecurityClient.Builder(tspAddress, apiKey).allowInsecureHttp(true).build());
  }

  public static String ensureLeadingColon(String input) {
    if (input == null || input.isEmpty()) {
      return ":";
    }
    return input.charAt(0) == ':' ? input : ":" + input;
  }
}
