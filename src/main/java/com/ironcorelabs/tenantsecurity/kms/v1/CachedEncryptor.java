package com.ironcorelabs.tenantsecurity.kms.v1;

/**
 * A cached document encryptor that holds a DEK for repeated encrypt operations without making
 * additional TSP wrap calls. All documents encrypted with this instance share the same DEK/EDEK
 * pair.
 *
 * <p>
 * Instances are created via {@link TenantSecurityClient#createCachedEncryptor(DocumentMetadata)} or
 * {@link TenantSecurityClient#withCachedEncryptor}. The cached key should be closed when done to
 * securely zero the DEK.
 *
 * @see TenantSecurityClient#createCachedEncryptor(DocumentMetadata)
 * @see TenantSecurityClient#withCachedEncryptor(DocumentMetadata, java.util.function.Function)
 */
public interface CachedEncryptor extends DocumentEncryptor, CachedKeyLifecycle {
}
