package com.ironcorelabs.tenantsecurity.kms.v1;


import org.testng.annotations.Test;

@Test(groups = {"unit"})
public class KMSClientTest {
  @Test(expectedExceptions = IllegalArgumentException.class)
  public void constructorUrlTest() throws Exception {
    new TenantSecurityClient.Builder("foobaz", "apiKey").build().close();
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void missingApiKeyTest() throws Exception {
    new TenantSecurityClient.Builder("https://localhost", null).build().close();
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void emptyApiKeyTest() throws Exception {
    new TenantSecurityClient.Builder("https://localhost", "").build().close();
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void httpsOnlyIsOnAndTryToUseHttpTest() throws Exception {
    new TenantSecurityClient.Builder("http://localhost", "apiKey").build().close();
  }

  // Just a sanity check to ensure the default allows https
  public void httpsOnlyIsOnAndTryToUseHttpsTest() throws Exception {
    new TenantSecurityClient.Builder("https://localhost", "apiKey").build().close();
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void invalidRequestThreadpoolSize() throws Exception {
    new TenantSecurityClient.Builder("https://localhost", "apiKey").requestThreadSize(0).build()
        .close();
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  public void invalidCryptoThreadpoolSize() throws Exception {
    new TenantSecurityClient.Builder("https://localhost", "apiKey").aesThreadSize(0).build()
        .close();
  }
}
