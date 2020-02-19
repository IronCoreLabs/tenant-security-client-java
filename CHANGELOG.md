# Changelog

## v2.0.0

- Deprecated the list based versions of `TenantSecurityKMSClient.decryptBatch` and `TenantSecurityKMSClient.encryptBatch` in favor of a Map based interface that allows for partial failure.

## v1.2.2

- Deprecated `TenantSecurityKMSException.getErrorMessage` in favor of `getMessage` to make the full error message more accessible.
- All `TenantSecurityKMSException` constructors accept/set an `Exception.cause` if possible.

## v1.2.1

- Added an error message to the `TenantSecurityKMSException` error that occurs when requests to the Tenant Security Proxy could not be made. This error message will include the URL that was attempted to be reached and the error text from the original exception that occurred. The error code associated with this error will be `UNABLE_TO_MAKE_REQUEST`.

## v1.2.0

- Added additional error codes to the `TenantSecurityKMSErrorCodes` enum for errors specific to failures when interacting with the tenants KMS. These errors will help differentiate between KMS errors that were caused by network outages, credential errors, etc so that the appropriate error can be communicated to the calling client.
  - `KMS_AUTHORIZATION_FAILED`: Requests to the tenants KMS failed because the credentials provided in their config failed to authenticate against their KMS. This could be because the credentials were setup incorrectly or because they have been revoked/removed.
  - `KMS_CONFIGURATION_INVALID`: Requests to the tenants KMS failed because the KMS key configuration was invalid or the permissions for the key that is being wrapped/unwrapped have been revoked/removed. This could be because the key configuration was setup incorrectly or because the key has been revoked/removed.
  - `KMS_UNREACHABLE`: Requests to the tenants KMS failed because the KMS API wasn't reachable. This could be because of a temporarary network outage or service down situation. The Tenant Security Proxy will automatically perform a single retry for the request if this error occurs.
  - The existing `KMS_WRAP_FAILED`/`KMS_UNWRAP_FAILED` error codes will now only occur when the request to the tenants KMS was successful but did not return the expected response.
- The `TenantSecurityKMSException` class now also contains the error message returned from Tenant Security Proxy and can be retrieved by calling `ex.getErrorMessage()`. This message will have additional context for the error that occured within the Tenant Security Proxy and will be specific to the KMS type being used. This message should be very helpful in logs to determine why requests are failing to the tenants KMS.

## v1.1.1

- Fixed a bug where the user agent header send on requests to the Tenant Security Proxy would grow unbounded and eventually cause HTTP 413 errors.

## v1.1.0

- Added support for Java8 compatibility.

### Compatibility

This version of the Tenant Security Java Client will only work with version `1.2.0+` of the Tenant Security Proxy container.

## v1.0.0

### Compatibility

This version of the Tenant Security Java Client will only work with version `1.2.0+` of the Tenant Security Proxy container.
