package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Holds metadata fields as part of an encrypted document. Each encrypted document will have
 * metadata that associates it to a tenant ID, which service is accessing the data, its
 * classification, as well as optional fields for other arbitrary key/value pairs and a request ID
 * to send to the Tenant Security Proxy.
 */
public class DocumentMetadata {
  private final String tenantId;
  private final String requestingUserOrServiceId;
  private final String dataLabel;
  private final Map<String, String> otherData;
  private final String requestId;
  private final String sourceIp;
  private final String objectId;

  /**
   * Constructor for DocumentMetadata class which contains arbitrary key/value pairs and a unique
   * request ID to send to the Tenant Security Proxy.
   *
   * @param tenantId Unique ID of tenant that is performing the operation.
   * @param requestingUserOrServiceId Unique ID of user/service that is processing data.
   * @param dataLabel Classification of data being processed.
   * @param otherData Additional String key/value pairs to add to metadata.
   * @param requestId Unique ID that ties host application request ID to Tenant Security Proxy logs.
   * @param sourceIp IP address of the initiator of this document request.
   * @param objectId ID of the object/document being acted on in the host system.
   * @throws IllegalArgumentException If the provided tenantId is not set
   */
  public DocumentMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
      Map<String, String> otherData, String requestId, String sourceIp, String objectId)
      throws IllegalArgumentException {
    if (tenantId == null || tenantId.isEmpty()) {
      throw new IllegalArgumentException(
          "Tenant ID value must be provided as part of document metadata.");
    }
    if (requestingUserOrServiceId == null || requestingUserOrServiceId.isEmpty()) {
      throw new IllegalArgumentException(
          "Requesting user or service ID must be provided as part of document metadata.");
    }
    this.tenantId = tenantId;
    this.requestingUserOrServiceId = requestingUserOrServiceId;
    this.dataLabel = dataLabel;
    this.otherData = otherData == null ? new HashMap<String, String>() : otherData;
    this.requestId = requestId;
    this.sourceIp = sourceIp;
    this.objectId = objectId;
  }

  /**
   * Constructor for DocumentMetadata class which contains arbitrary key/value pairs and a unique
   * request ID to send to the Tenant Security Proxy.
   *
   * @param tenantId Unique ID of tenant that is performing the operation.
   * @param requestingUserOrServiceId Unique ID of user/service that is processing data.
   * @param dataLabel Classification of data being processed.
   * @param otherData Additional String key/value pairs to add to metadata.
   * @param requestId Unique ID that ties host application request ID to Tenant Security Proxy logs.
   * @throws IllegalArgumentException If the provided tenantId is not set
   */
  public DocumentMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
      Map<String, String> otherData, String requestId) {
    this(tenantId, requestingUserOrServiceId, dataLabel, otherData, requestId, null, null);
  }

  /**
   * Constructor for DocumentMetadata class which contains arbitrary key/value pairs to send to the
   * Tenant Security Proxy.
   *
   * @param tenantId Unique ID of tenant that is performing the operation.
   * @param requestingUserOrServiceId Unique ID of user/service that is processing data.
   * @param dataLabel Classification of data being processed.
   * @param otherData Additional String key/value pairs to add to metadata.
   * @throws IllegalArgumentException If the provided tenantId is not set
   */
  public DocumentMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
      Map<String, String> otherData) throws IllegalArgumentException {
    this(tenantId, requestingUserOrServiceId, dataLabel, otherData, null, null, null);
  }

  /**
   * Constructor for DocumentMetadata class which contains a unique request ID to send to the Tenant
   * Security Proxy.
   *
   * @param tenantId Unique ID of tenant that is performing the operation.
   * @param requestingUserOrServiceId Unique ID of user/service that is processing data.
   * @param dataLabel Classification of data being processed.
   * @param requestId Unique ID that ties host application request ID to Tenant Security Proxy logs.
   * @throws IllegalArgumentException If the provided tenantId is not set
   */
  public DocumentMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
      String requestId) {
    this(tenantId, requestingUserOrServiceId, dataLabel, null, requestId, null, null);
  }

  /**
   * Constructor for DocumentMetadata class which has no additional metadata.
   *
   * @param tenantId Unique ID of tenant that is performing the operation.
   * @param requestingUserOrServiceId Unique ID of user/service that is processing data.
   * @param dataLabel Classification of data being processed.
   * @throws IllegalArgumentException If the provided tenantId is not set
   */
  public DocumentMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel) {
    this(tenantId, requestingUserOrServiceId, dataLabel, null, null, null, null);
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
   * Convert all of the metadata into a HashMap that can be used to POST all the data to the Tenant
   * Security Proxy. Adds all standard fields to the Map and then builds up a sub object for any
   * custom fields.
   *
   * @return Metadata converted into POST data Map
   */
  public Map<String, Object> getAsPostData() {
    Map<String, Object> postData = new HashMap<>();
    postData.put("tenantId", tenantId);

    Map<String, Object> iclFields = new HashMap<>();
    iclFields.put("requestId", requestId);
    iclFields.put("sourceIp", sourceIp);
    iclFields.put("objectId", objectId);
    iclFields.put("requestingId", requestingUserOrServiceId);
    iclFields.put("dataLabel", dataLabel);
    iclFields.values().removeIf(Objects::isNull);
    postData.put("iclFields", iclFields);

    Map<String, String> customFields = new HashMap<>();
    for (Map.Entry<String, String> entry : otherData.entrySet()) {
      customFields.put(entry.getKey(), entry.getValue());
    }
    postData.put("customFields", customFields);
    return postData;
  }
}
