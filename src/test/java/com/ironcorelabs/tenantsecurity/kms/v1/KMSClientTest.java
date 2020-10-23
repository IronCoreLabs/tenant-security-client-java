package com.ironcorelabs.tenantsecurity.kms.v1;


import org.testng.annotations.Test;

@Test(groups = { "unit" })
public class KMSClientTest {
    @Test(expectedExceptions = java.net.MalformedURLException.class)
    public void constructorUrlTest() throws Exception {
        new TenantSecurityClient("foobaz", "apiKey");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void missingApiKeyTest() throws Exception {
        new TenantSecurityClient("http://localhost", null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void emptyApiKeyTest() throws Exception {
        new TenantSecurityClient("http://localhost", "");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void invalidRequestThreadpoolSize() throws Exception {
        new TenantSecurityClient("http://localhost", "apiKey", 0, 1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void invalidCryptoThreadpoolSize() throws Exception {
        new TenantSecurityClient("http://localhost", "apiKey", 1, 0);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void missingRandomGen() throws Exception {
        new TenantSecurityClient("http://localhost", "apiKey",
                TenantSecurityClient.DEFAULT_REQUEST_THREADPOOL_SIZE,
                TenantSecurityClient.DEFAULT_AES_THREADPOOL_SIZE, null);
    }
}