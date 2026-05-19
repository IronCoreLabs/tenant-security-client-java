package com.ironcorelabs.tenantsecurity.kms.v1;


import org.testng.annotations.Test;

@Test(groups = {"unit"})
public class DeterministicClientTest {
  @Test(expectedExceptions = IllegalArgumentException.class)
  public void invalidReadTimeoutOnSixArgConstructor() throws Exception {
    new DeterministicTenantSecurityClient("https://localhost", "apiKey", 1, 1, 0, 1000).close();
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void invalidConnectTimeoutOnSixArgConstructor() throws Exception {
    new DeterministicTenantSecurityClient("https://localhost", "apiKey", 1, 1, 1000, 0).close();
  }

  // Sanity check that the 6-arg constructor builds successfully with distinct read and connect
  // timeouts.
  public void independentReadAndConnectTimeoutsOnSixArgConstructor() throws Exception {
    new DeterministicTenantSecurityClient("https://localhost", "apiKey", 1, 1, 30000, 2000).close();
  }
}
