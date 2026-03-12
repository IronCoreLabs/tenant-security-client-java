package com.ironcorelabs.tenantsecurity.kms.v1;

/**
 * A cached document decryptor that holds a DEK for repeated decrypt operations without making
 * additional TSP unwrap calls. Can only decrypt documents that were encrypted with the same
 * DEK/EDEK pair.
 *
 * <p>
 * Instances are created via
 * {@link TenantSecurityClient#createCachedDecryptor(String, DocumentMetadata)} or
 * {@link TenantSecurityClient#withCachedDecryptor}. The cached key should be closed when done to
 * securely zero the DEK.
 *
 * @see TenantSecurityClient#createCachedDecryptor(String, DocumentMetadata)
 * @see TenantSecurityClient#withCachedDecryptor(String, DocumentMetadata,
 *      java.util.function.Function)
 */
public interface CachedDecryptor extends DocumentDecryptor, CachedKeyLifecycle {
}
