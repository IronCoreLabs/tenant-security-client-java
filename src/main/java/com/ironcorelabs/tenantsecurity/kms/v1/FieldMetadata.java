package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Map;

/**
 * Holds metadata fields as part of a deterministically encrypted field. Each encrypted field will
 * have metadata that associates it to a tenant ID, which service is accessing the data, its
 * classification, as well as optional fields for other arbitrary key/value pairs and a request ID
 * to send to the Tenant Security Proxy.
 */
public class FieldMetadata extends Metadata {
  /**
   * Constructor for FieldMetadata class which contains arbitrary key/value pairs and a unique
   * request ID to send to the Tenant Security Proxy.
   *
   * @param tenantId Unique ID of tenant that is performing the operation.
   * @param requestingUserOrServiceId Unique ID of user/service that is processing data.
   * @param dataLabel Classification of data being processed.
   * @param otherData Additional String key/value pairs to add to metadata.
   * @param requestId Unique ID that ties host application request ID to Tenant Security Proxy logs.
   * @param sourceIp IP address of the initiator of this request.
   * @param objectId ID of the object being acted on in the host system.
   * @throws IllegalArgumentException If the provided tenantId is not set
   */
  public FieldMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
      Map<String, String> otherData, String requestId, String sourceIp, String objectId)
      throws IllegalArgumentException {
    super(tenantId, requestingUserOrServiceId, dataLabel, otherData, requestId, sourceIp, objectId);
  }

  /**
   * Constructor for FieldMetadata class which contains arbitrary key/value pairs and a unique
   * request ID to send to the Tenant Security Proxy.
   *
   * @param tenantId Unique ID of tenant that is performing the operation.
   * @param requestingUserOrServiceId Unique ID of user/service that is processing data.
   * @param dataLabel Classification of data being processed.
   * @param otherData Additional String key/value pairs to add to metadata.
   * @param requestId Unique ID that ties host application request ID to Tenant Security Proxy logs.
   * @throws IllegalArgumentException If the provided tenantId is not set
   */
  public FieldMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
      Map<String, String> otherData, String requestId) {
    this(tenantId, requestingUserOrServiceId, dataLabel, otherData, requestId, null, null);
  }

  /**
   * Constructor for FieldMetadata class which contains arbitrary key/value pairs to send to the
   * Tenant Security Proxy.
   *
   * @param tenantId Unique ID of tenant that is performing the operation.
   * @param requestingUserOrServiceId Unique ID of user/service that is processing data.
   * @param dataLabel Classification of data being processed.
   * @param otherData Additional String key/value pairs to add to metadata.
   * @throws IllegalArgumentException If the provided tenantId is not set
   */
  public FieldMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
      Map<String, String> otherData) throws IllegalArgumentException {
    this(tenantId, requestingUserOrServiceId, dataLabel, otherData, null, null, null);
  }

  /**
   * Constructor for FieldMetadata class which contains a unique request ID to send to the Tenant
   * Security Proxy.
   *
   * @param tenantId Unique ID of tenant that is performing the operation.
   * @param requestingUserOrServiceId Unique ID of user/service that is processing data.
   * @param dataLabel Classification of data being processed.
   * @param requestId Unique ID that ties host application request ID to Tenant Security Proxy logs.
   * @throws IllegalArgumentException If the provided tenantId is not set
   */
  public FieldMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel,
      String requestId) {
    this(tenantId, requestingUserOrServiceId, dataLabel, null, requestId, null, null);
  }

  /**
   * Constructor for FieldMetadata class which has no additional metadata.
   *
   * @param tenantId Unique ID of tenant that is performing the operation.
   * @param requestingUserOrServiceId Unique ID of user/service that is processing data.
   * @param dataLabel Classification of data being processed.
   * @throws IllegalArgumentException If the provided tenantId is not set
   */
  public FieldMetadata(String tenantId, String requestingUserOrServiceId, String dataLabel) {
    this(tenantId, requestingUserOrServiceId, dataLabel, null, null, null, null);
  }
}
