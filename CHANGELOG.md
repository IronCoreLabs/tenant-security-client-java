# Changelog

## v6.0.0

- Added `DeterministicTenantSecurityClient` supporting deterministic encryption/decryption operations.
- Changed minimum supported Java version to 11.
- Removed deprecated `TenantSecurityClient.rekeyDocument` method.
- Added `TscException` for exceptions originating from the TSC.

### Compatibility

Deterministic encryption functionality requires TSP 4.11.1+.

## v4.2.0

- Added `KmsException` for `KmsThrottled`.

### Compatibility

This new error code will only be returned by TSP 4.4.1+.

## v4.1.0

- Added `TenantSecurityClient.rekeyEdek` method
- Deprecated `TenantSecurityClient.rekeyDocument` method

## v4.0.1

- Remove javax.annotation from the shaded jar.

## v4.0.0

- Shade google-http-client and all related jars to increase compatibility with conflicting versions.
- No public api changes, but bumping major version since we've changed the contents of our jar significantly.

## v3.1.1

- No public api changes. Internal change to increase compatibility with 1.20 google-http-client.

## v3.1.0

- Added `TenantSecurityClient.rekeyDocument` method and supporting `RekeyedDocumentKey` type

## v3.0.1

- Renamed some security events for better consistency

## v3.0.0

- Added `TenantSecurityClient.logSecurityEvent` method and supporting `SecurityEvent` and `EventMetadata` types
- Standardized `EventMetadata` and `DocumentMetadata` to similar interfaces with the TSP
- Introduced an exception hierarchy based on TSP error codes. `TenantSecurityKMSException` renamed to `TenantSecurityException` and
  `KmsException`, `SecurityEventException`, and `TspServiceException` are subclasses.
- Renamed `TenantSecurityKMSClient` to `TenantSecurityClient`
- Removed deprecated list based batch methods

### Compatibility

This version of the Tenant Security Java Client will only work with version `3.0.0+` of the Tenant Security Proxy container.

## v2.0.3

- Use connection pooling for better performance and safer scaling in high-load environments.
- Bumped versions of HTTP libs

## v2.0.2

- Added a `timeout` option to the `TenantSecurityKMSClient` this timeout is applied to the connection negotiation _and_ the read from the TSP, so the worst case of a very unstable connection is 2x the `timeout` value.

## v2.0.1

- Fixed displayed URL in error message when TSP unwrap endpoint cannot be reached.

## v2.0.0

- Deprecated the list based versions of `TenantSecurityKMSClient.decryptBatch` and `TenantSecurityKMSClient.encryptBatch` in favor of a Map based interface that allows for partial failure.

### Compatibility

This version of the Tenant Security Java Client will only work with version `>= 2.0.0 < 4.0.0` of the Tenant Security Proxy container due to a deprecated interface. `TSP v3` supports both the old and new interfaces and can be used to migrate TSCs if necessary.

## v1.2.2

- Deprecated `TenantSecurityKMSException.getErrorMessage` in favor of `getMessage` to make the full error message more accessible.
- All `TenantSecurityKMSException` constructors accept/set an `Exception.cause` if possible.

## v1.2.1

- Added an error message to the `TenantSecurityKMSException` error that occurs when requests to the Tenant Security Proxy could not be made. This error message will include the URL that was attempted to be reached and the error text from the original exception that occurred. The error code associated with this error will be `UNABLE_TO_MAKE_REQUEST`.

## v1.2.0

- Added additional error codes to the `TenantSecurityKMSErrorCodes` enum for errors specific to failures when interacting with the tenants KMS. These errors will help differentiate between KMS errors that were caused by network outages, credential errors, etc so that the appropriate error can be communicated to the calling client.
  - `KMS_AUTHORIZATION_FAILED`: Requests to the tenants KMS failed because the credentials provided in their config failed to authenticate against their KMS. This could be because the credentials were setup incorrectly or because they have been revoked/removed.
  - `KMS_CONFIGURATION_INVALID`: Requests to the tenants KMS failed because the KMS key configuration was invalid or the permissions for the key that is being wrapped/unwrapped have been revoked/removed. This could be because the key configuration was setup incorrectly or because the key has been revoked/removed.
  - `KMS_UNREACHABLE`: Requests to the tenants KMS failed because the KMS API wasn't reachable. This could be because of a temporary network outage or service down situation. The Tenant Security Proxy will automatically perform a single retry for the request if this error occurs.
  - The existing `KMS_WRAP_FAILED`/`KMS_UNWRAP_FAILED` error codes will now only occur when the request to the tenants KMS was successful but did not return the expected response.
- The `TenantSecurityKMSException` class now also contains the error message returned from Tenant Security Proxy and can be retrieved by calling `ex.getErrorMessage()`. This message will have additional context for the error that occurred within the Tenant Security Proxy and will be specific to the KMS type being used. This message should be very helpful in logs to determine why requests are failing to the tenants KMS.

## v1.1.1

- Fixed a bug where the user agent header send on requests to the Tenant Security Proxy would grow unbounded and eventually cause HTTP 413 errors.

## v1.1.0

- Added support for Java8 compatibility.

### Compatibility

This version of the Tenant Security Java Client will only work with version `>= 1.2.0 < 4.0.0` of the Tenant Security Proxy container due to a deprecated interface. `TSP v3` supports both the old and new interfaces and can be used to migrate TSCs if necessary.

## v1.0.0

### Compatibility

This version of the Tenant Security Java Client will only work with version `>= 1.2.0 < 4.0.0` of the Tenant Security Proxy container due to a deprecated interface. `TSP v3` supports both the old and new interfaces and can be used to migrate TSCs if necessary.
