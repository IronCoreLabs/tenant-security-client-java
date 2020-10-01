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
    public void missingTenantId() throws Exception {
        new EventMetadata(null, "serviceID", "label");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void emptyTenantId() throws Exception {
        new EventMetadata("", "serviceID", "label");
    }

    public void defaultValueForAdditionalData() throws Exception {
        EventMetadata meta = new EventMetadata("tenantId", "serviceID", "label");
        assertTrue(meta.getOtherData() instanceof HashMap<?, ?>);
    }

    public void defaultValueForRequestId() throws Exception {
        EventMetadata meta = new EventMetadata("tenantId", "serviceID", "label");
        assertEquals(meta.getRequestId(), null);
    }

    @SuppressWarnings("unchecked")
    public void testGetAsPostDataPartial() throws Exception {
        EventMetadata meta = new EventMetadata("customerID", "svcID", "classification");

        Map<String, Object> postData = meta.getAsPostData();
        assertEquals(postData.get("tenantId"), "customerID");
        Long roughlyNow = (Long) postData.get("timestampMillis");
        long now = java.lang.System.currentTimeMillis();
        long delta = now - roughlyNow;
        assertTrue(delta < 1000 && delta > -1);

        Map<String, String> customData = (Map<String, String>) postData.get("customFields");
        assertEquals(customData.size(), 0);

        Map<String, Object> ironcoreData = (Map<String, Object>) postData.get("ironcoreFields");
        assertEquals(ironcoreData.get("requestingId"), "svcID");
        assertEquals(ironcoreData.get("dataLabel"), "classification");
        assertEquals(ironcoreData.get("requestId"), null);
        assertEquals(ironcoreData.get("sourceIp"), null);
        assertEquals(ironcoreData.get("objectId"), null);
    }

    @SuppressWarnings("unchecked")
    public void testGetAsPostDataFull() throws Exception {
        Map<String, String> arbData = new HashMap<>();
        long nowInQuotes = java.lang.System.currentTimeMillis();
        arbData.put("custom", "field");
        arbData.put("other", "value");
        EventMetadata meta = new EventMetadata("customerID", "svcID", "classification", arbData,
                "requestId", "8.8.8.8", "document-5", nowInQuotes);

        Map<String, Object> postData = meta.getAsPostData();
        assertEquals(postData.get("tenantId"), "customerID");
        assertEquals(postData.get("timestampMillis"), nowInQuotes);

        Map<String, String> customData = (Map<String, String>) postData.get("customFields");
        assertEquals(customData.get("custom"), "field");
        assertEquals(customData.get("other"), "value");

        Map<String, Object> ironcoreData = (Map<String, Object>) postData.get("ironcoreFields");
        assertEquals(ironcoreData.get("requestingId"), "svcID");
        assertEquals(ironcoreData.get("dataLabel"), "classification");
        assertEquals(ironcoreData.get("requestId"), "requestId");
        assertEquals(ironcoreData.get("sourceIp"), "8.8.8.8");
        assertEquals(ironcoreData.get("objectId"), "document-5");
    }
}
