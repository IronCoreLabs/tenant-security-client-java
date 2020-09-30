package com.ironcorelabs.tenantsecurity.logdriver.v1;

import java.util.HashMap;
import java.util.Map;

/**
 * Holds metadata fields as part of a security event. Each event will have metadata that associates
 * it to a tenant ID, which service is accessing the data, it's classification, as well as optional
 * fields for other arbitrary key/value pairs and a request ID to send to the Tenant Security Proxy.
 */
public class EventMetadata {
    private final String tenantId;
    private final String requestingUserOrServiceId;
    private final String requestId;
    private final String dataLabel;
    private final String sourceIp;
    private final String objectId;
    private final long timestampMillis;
    private final Map<String, String> otherData;

    /**
     * Constructor for EventMetadata class which contains arbitrary key/value pairs and a unique
     * request ID to send to the Tenant Security Proxy.
     *
     * @param tenantId                  Unique ID of tenant that is performing the operation.
     * @param requestingUserOrServiceId Unique ID of user/service that triggered the event.
     * @param dataLabel                 Classification of the event if more than the event category
     *                                  is needed.
     * @param otherData                 Additional String key/value pairs to add to metadata.
     * @param requestId                 Unique ID that ties host application request ID to Tenant
     *                                  Security Proxy logs.
     * @param sourceIp                  IP address of the initiator of the event.
     * @param objectId                  ID of the object being acted on when the event occured.
     * @param timestampMillis           Linux epoch millis of when the event occured. If this isn't
     *                                  passed, now will be assumed.
     * @throws IllegalArgumentException If the provided tenantId is not set
     */
    public EventMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
            Map<String, String> otherData, String requestId, String sourceIp, String objectId,
            Long timestampMillis) throws IllegalArgumentException {
        if (tenantId == null || tenantId.isEmpty()) {
            throw new IllegalArgumentException(
                    "Tenant ID value must be provided as part of document metadata.");
        }
        this.tenantId = tenantId;
        this.requestingUserOrServiceId = requestingUserOrServiceId;
        this.requestId = requestId;
        this.dataLabel = dataLabel;
        this.sourceIp = sourceIp;
        this.objectId = objectId;
        this.timestampMillis =
                timestampMillis == null ? java.lang.System.currentTimeMillis() : timestampMillis;
        this.otherData = otherData == null ? new HashMap<String, String>() : otherData;
    }

    /**
     * Constructor for EventMetadata class which contains arbitrary key/value pairs and a unique
     * request ID to send to the Tenant Security Proxy.
     *
     * @param tenantId                  Unique ID of tenant that is performing the operation.
     * @param requestingUserOrServiceId Unique ID of user/service that triggered the event.
     * @param dataLabel                 Classification of the event if more than the event category
     *                                  is needed.
     * @param otherData                 Additional String key/value pairs to add to metadata.
     * @param requestId                 Unique ID that ties host application request ID to Tenant
     *                                  Security Proxy logs.
     * @throws IllegalArgumentException If the provided tenantId is not set
     */
    public EventMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
            Map<String, String> otherData, String requestId) {
        this(tenantId, requestingUserOrServiceId, dataLabel, otherData, requestId, null, null,
                null);
    }

    /**
     * Constructor for EventMetadata class which contains arbitrary key/value pairs to send to the
     * Tenant Security Proxy.
     *
     * @param tenantId                  Unique ID of tenant that is performing the operation.
     * @param requestingUserOrServiceId Unique ID of user/service that triggered the event.
     * @param dataLabel                 Classification of the event if more than the event category
     *                                  is needed.
     * @param otherData                 Additional String key/value pairs to add to metadata.
     * @throws IllegalArgumentException If the provided tenantId is not set
     */
    public EventMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
            Map<String, String> otherData) throws IllegalArgumentException {
        this(tenantId, requestingUserOrServiceId, dataLabel, otherData, null, null, null, null);
    }

    /**
     * Constructor for EventMetadata class which contains a unique request ID to send to the Tenant
     * Security Proxy.
     *
     * @param tenantId                  Unique ID of tenant that is performing the operation.
     * @param requestingUserOrServiceId Unique ID of user/service that triggered the event.
     * @param dataLabel                 Classification of the event if more than the event category
     *                                  is needed.
     * @param requestId                 Unique ID that ties host application request ID to Tenant
     *                                  Security Proxy logs.
     * @throws IllegalArgumentException If the provided tenantId is not set
     */
    public EventMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
            String requestId) {
        this(tenantId, requestingUserOrServiceId, dataLabel, null, requestId, null, null, null);
    }

    /**
     * Constructor for EventMetadata class which has no additional metadata.
     *
     * @param tenantId                  Unique ID of tenant that is performing the operation.
     * @param requestingUserOrServiceId Unique ID of user/service that triggered the event.
     * @param dataLabel                 Classification of the event if more than the event category
     *                                  is needed.
     * @throws IllegalArgumentException If the provided tenantId is not set
     */
    public EventMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel) {
        this(tenantId, requestingUserOrServiceId, dataLabel, null, null, null, null, null);
    }

    /**
     * Get the tenant ID.
     *
     * @return Metadata tenant ID
     */
    public String getTenantId() {
        return tenantId;
    }

    /**
     * Get the requesting user or service ID.
     *
     * @return Requesting user or service ID
     */
    public String getRequestingUserOrServiceId() {
        return requestingUserOrServiceId;
    }

    /**
     * Get the provided request ID
     *
     * @return Unique ID that ties host application request ID to Tenant Security Proxy logs.
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * Get the data classification label.
     *
     * @return Data classification label
     */
    public String getDataLabel() {
        return dataLabel;
    }

    /**
     * Get any other metadata.
     *
     * @return Any other key/value metadata
     */
    public Map<String, String> getOtherData() {
        return otherData;
    }

    /**
     * Convert all of the metadata into a HashMap that can be used to POST all the data to the
     * Tenant Security Proxy. Adds all standard fields to the Map and then builds up a sub object
     * for any custom fields.
     *
     * @return Metadata converted into POST data Map
     */
    public Map<String, Object> getAsPostData() {
        Map<String, Object> postData = new HashMap<>();
        postData.put("tenantId", tenantId);
        postData.put("timestampMillis", timestampMillis);

        Map<String, String> customFields = new HashMap<>();
        for (Map.Entry<String, String> entry : otherData.entrySet()) {
            customFields.put(entry.getKey(), entry.getValue());
        }
        if (requestId != null) {
            customFields.put("requestId", requestId);
        }
        customFields.put("sourceIp", sourceIp);
        customFields.put("objectId", objectId);
        customFields.put("requestingId", requestingUserOrServiceId);
        customFields.put("dataLabel", dataLabel);
        postData.put("customFields", customFields);
        return postData;
    }
}
