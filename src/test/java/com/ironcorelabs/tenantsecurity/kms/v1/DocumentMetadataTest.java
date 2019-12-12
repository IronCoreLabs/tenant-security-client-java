package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.testng.annotations.Test;

@Test(groups = { "unit" })
public class DocumentMetadataTest {
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void missingTenantID() throws Exception {
        new DocumentMetadata(null, "serviceID", "label");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void emptyTenantID() throws Exception {
        new DocumentMetadata("", "serviceID", "label");
    }

    public void defaultValueForAdditionalData() throws Exception {
        DocumentMetadata meta = new DocumentMetadata("tenantID", "serviceID", "label");
        assertTrue(meta.getOtherData() instanceof HashMap<?, ?>);
    }

    public void defaultValueForRequestId() throws Exception {
        DocumentMetadata meta = new DocumentMetadata("tenantID", "serviceID", "label");
        assertEquals(meta.getRequestId(), null);
    }

    @SuppressWarnings("unchecked")
    public void testGetAsPostDataPartial() throws Exception {
        DocumentMetadata meta = new DocumentMetadata("customerID", "svcID", "classification");

        Map<String, Object> postData = meta.getAsPostData();
        assertEquals(postData.get("tenantID"), "customerID");
        assertEquals(postData.get("requestingID"), "svcID");
        assertEquals(postData.get("dataLabel"), "classification");
        assertEquals(postData.get("requestID"), null);

        Map<String, String> customData = (Map<String, String>) postData.get("customFields");
        assertEquals(customData.size(), 0);
    }

    @SuppressWarnings("unchecked")
    public void testGetAsPostDataFull() throws Exception {
        Map<String, String> arbData = new HashMap<>();
        arbData.put("custom", "field");
        arbData.put("other", "value");
        DocumentMetadata meta = new DocumentMetadata("customerID", "svcID", "classification", arbData, "requestID");

        Map<String, Object> postData = meta.getAsPostData();
        assertEquals(postData.get("tenantID"), "customerID");
        assertEquals(postData.get("requestingID"), "svcID");
        assertEquals(postData.get("dataLabel"), "classification");
        assertEquals(postData.get("requestID"), "requestID");

        Map<String, String> customData = (Map<String, String>) postData.get("customFields");
        assertEquals(customData.get("custom"), "field");
        assertEquals(customData.get("other"), "value");
    }
}