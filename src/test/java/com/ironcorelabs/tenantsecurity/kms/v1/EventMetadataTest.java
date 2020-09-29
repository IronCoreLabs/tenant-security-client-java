package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;
import java.util.HashMap;
import java.util.Map;
import com.ironcorelabs.tenantsecurity.logdriver.v1.EventMetadata;
import org.testng.annotations.Test;

@Test(groups = {"unit"})
public class EventMetadataTest {
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void missingTenantID() throws Exception {
        new EventMetadata(null, "serviceID", "label");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void emptyTenantID() throws Exception {
        new EventMetadata("", "serviceID", "label");
    }

    public void defaultValueForAdditionalData() throws Exception {
        EventMetadata meta = new EventMetadata("tenantID", "serviceID", "label");
        assertTrue(meta.getOtherData() instanceof HashMap<?, ?>);
    }

    public void defaultValueForRequestId() throws Exception {
        EventMetadata meta = new EventMetadata("tenantID", "serviceID", "label");
        assertEquals(meta.getRequestId(), null);
    }

    @SuppressWarnings("unchecked")
    public void testGetAsPostDataPartial() throws Exception {
        EventMetadata meta = new EventMetadata("customerID", "svcID", "classification");

        Map<String, Object> postData = meta.getAsPostData();
        assertEquals(postData.get("tenantID"), "customerID");
        assertEquals(postData.get("requestingID"), "svcID");
        assertEquals(postData.get("dataLabel"), "classification");
        assertEquals(postData.get("requestID"), null);
        assertEquals(postData.get("sourceIP"), null);
        assertEquals(postData.get("objectID"), null);
        Long roughlyNow = (Long) postData.get("timestampMillis");
        long now = java.lang.System.currentTimeMillis();
        long delta = now - roughlyNow;
        assertTrue(delta < 1000 && delta > -1);

        Map<String, String> customData = (Map<String, String>) postData.get("customFields");
        assertEquals(customData.size(), 0);
    }

    @SuppressWarnings("unchecked")
    public void testGetAsPostDataFull() throws Exception {
        Map<String, String> arbData = new HashMap<>();
        long nowInQuotes = java.lang.System.currentTimeMillis();
        arbData.put("custom", "field");
        arbData.put("other", "value");
        EventMetadata meta = new EventMetadata("customerID", "svcID", "classification", arbData,
                "requestID", "8.8.8.8", "document-5", nowInQuotes);

        Map<String, Object> postData = meta.getAsPostData();
        assertEquals(postData.get("tenantID"), "customerID");
        assertEquals(postData.get("requestingID"), "svcID");
        assertEquals(postData.get("dataLabel"), "classification");
        assertEquals(postData.get("requestID"), "requestID");
        assertEquals(postData.get("sourceIP"), "8.8.8.8");
        assertEquals(postData.get("objectID"), "document-5");
        assertEquals(postData.get("timestampMillis"), nowInQuotes);

        Map<String, String> customData = (Map<String, String>) postData.get("customFields");
        assertEquals(customData.get("custom"), "field");
        assertEquals(customData.get("other"), "value");
    }
}
