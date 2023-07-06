package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

abstract class Metadata {
  private String tenantId;
  private String requestingUserOrServiceId;
  private String dataLabel;
  private Map<String, String> otherData;
  private String requestId;
  private String sourceIp;
  private String objectId;

  Metadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
      Map<String, String> otherData, String requestId, String sourceIp, String objectId)
      throws IllegalArgumentException {
    if (tenantId == null || tenantId.isEmpty()) {
      throw new IllegalArgumentException("Tenant ID value must be provided as part of metadata.");
    }
    if (requestingUserOrServiceId == null || requestingUserOrServiceId.isEmpty()) {
      throw new IllegalArgumentException(
          "Requesting user or service ID must be provided as part of metadata.");
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
   * Get the tenant ID.
   *
   * @return Metadata tenant ID
   */
  public final String getTenantId() {
    return tenantId;
  }

  /**
   * Get the requesting user or service ID.
   *
   * @return Requesting user or service ID
   */
  public final String getRequestingUserOrServiceId() {
    return requestingUserOrServiceId;
  }

  /**
   * Get the provided request ID
   *
   * @return Unique ID that ties host application request ID to Tenant Security Proxy logs.
   */
  public final String getRequestId() {
    return requestId;
  }

  /**
   * Get the data classification label.
   *
   * @return Data classification label
   */
  public final String getDataLabel() {
    return dataLabel;
  }

  /**
   * Get any other metadata.
   *
   * @return Any other key/value metadata
   */
  public final Map<String, String> getOtherData() {
    return otherData;
  }

  /**
   * Convert all of the metadata into a HashMap that can be used to POST all the data to the Tenant
   * Security Proxy. Adds all standard fields to the Map and then builds up a sub object for any
   * custom fields.
   *
   * @return Metadata converted into POST data Map
   */
  final Map<String, Object> getAsPostData() {
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
