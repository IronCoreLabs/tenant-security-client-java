package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.ironcorelabs.tenantsecurity.kms.v1.exception.KmsException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.SecurityEventException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TspServiceException;
import org.testng.annotations.Test;

@Test(groups = { "dev-integration" })
public class KMSRequestTest {
    private DocumentMetadata getMetadata() {
        Map<String, String> arbData = new HashMap<>();
        arbData.put("thingOne", "valuetwo");
        return new DocumentMetadata(NotPrimaryAndDisabledConfigs.MULTIPLE_TENANT_ID, "integrationTest", "sample",
                arbData);
    }

    private Map<String, byte[]> getDocument() {
        Map<String, byte[]> documentMap = new HashMap<>();
        try {
            documentMap.put("doc", "Fake data".getBytes("UTF-8"));
        } catch (Exception e) {
        }
        return documentMap;
    }

    public void errorCodeWhenServiceNotReachable() throws Exception {
        CompletableFuture<EncryptedDocument> encrypt = TenantSecurityClient
                .create("http://thisdomaindoesnotexist.eta", "apiKey")
                .thenCompose(client -> client.encrypt(getDocument(), getMetadata()));

        try {
            encrypt.get();
            fail("Request should fail when host is unreachable.");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TenantSecurityException);
            TenantSecurityException esError = (TenantSecurityException) e.getCause();
            assertNotNull(esError.getCause());
            assertEquals(esError.getErrorCode(), TenantSecurityErrorCodes.UNABLE_TO_MAKE_REQUEST);
        }
    }

    public void errorCodeWhenApiKeyIsWrong() throws Exception {
        CompletableFuture<EncryptedDocument> encrypt = TenantSecurityClient
                .create(TestSettings.TSP_ADDRESS + TestSettings.TSP_PORT, "wrongKey")
                .thenCompose(client -> client.encrypt(getDocument(), getMetadata()));

        try {
            encrypt.get();
            fail("Request should fail when API key is wrong");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TenantSecurityException);
            TenantSecurityException esError = (TenantSecurityException) e.getCause();
            assertEquals(esError.getErrorCode(), TenantSecurityErrorCodes.UNAUTHORIZED_REQUEST);
        }
    }

    public void errorCodeWhenEdekFormatIsWrong() throws Exception {
        Map<String, byte[]> documentMap = new HashMap<>();
        documentMap.put("doc", new byte[] { 3, 73, 82, 79, 78 });
        EncryptedDocument eDoc = new EncryptedDocument(documentMap, "d2hhdCBhIHdhc3RlIG9mIHRpbWUK");

        CompletableFuture<PlaintextDocument> decrypt = TenantSecurityClient
                .create(TestSettings.TSP_ADDRESS + TestSettings.TSP_PORT,
                        NotPrimaryAndDisabledConfigs.INTEGRATION_API_KEY)
                .thenCompose(client -> client.decrypt(eDoc, getMetadata()));

        try {
            decrypt.get();
            fail("Request should fail when API key is wrong");
        } catch (ExecutionException e) {
            assertTrue(e.getCause() instanceof TenantSecurityException);
            TenantSecurityException esError = (TenantSecurityException) e.getCause();
            assertEquals(esError.getErrorCode(), TenantSecurityErrorCodes.INVALID_PROVIDED_EDEK);
        }
    }

    public void exceptionFromErrorResponseTspServiceException() throws Exception {
        final String staticMsg = "static message";
        final int staticHttpCode = 42;

        // TspServiceException
        ErrorResponse unableToMakeReqError = new ErrorResponse(
                TenantSecurityErrorCodes.UNABLE_TO_MAKE_REQUEST.getCode(), staticMsg);
        TenantSecurityException unableToMakeReqException = unableToMakeReqError
                .toTenantSecurityException(staticHttpCode);
        assertTspServiceException(staticMsg, staticHttpCode, unableToMakeReqException,
                TenantSecurityErrorCodes.UNABLE_TO_MAKE_REQUEST);

        ErrorResponse unknownErrResp = new ErrorResponse(TenantSecurityErrorCodes.UNKNOWN_ERROR.getCode(), staticMsg);
        TenantSecurityException unknownErrException = unknownErrResp.toTenantSecurityException(staticHttpCode);
        assertTspServiceException(staticMsg, staticHttpCode, unknownErrException,
                TenantSecurityErrorCodes.UNKNOWN_ERROR);

        ErrorResponse invalidRequestBody = new ErrorResponse(TenantSecurityErrorCodes.INVALID_REQUEST_BODY.getCode(),
                staticMsg);
        TenantSecurityException invalidRequestException = invalidRequestBody.toTenantSecurityException(staticHttpCode);
        assertTspServiceException(staticMsg, staticHttpCode, invalidRequestException,
                TenantSecurityErrorCodes.INVALID_REQUEST_BODY);

        ErrorResponse unauthorizedReqErrResp = new ErrorResponse(
                TenantSecurityErrorCodes.UNAUTHORIZED_REQUEST.getCode(), staticMsg);
        TenantSecurityException unauthorizedReqException = unauthorizedReqErrResp
                .toTenantSecurityException(staticHttpCode);
        assertTspServiceException(staticMsg, staticHttpCode, unauthorizedReqException,
                TenantSecurityErrorCodes.UNAUTHORIZED_REQUEST);

        // KmsException
        ErrorResponse noPrimaryKmsResp = new ErrorResponse(
                TenantSecurityErrorCodes.NO_PRIMARY_KMS_CONFIGURATION.getCode(), staticMsg);
        TenantSecurityException noPrimaryKmsException = noPrimaryKmsResp.toTenantSecurityException(staticHttpCode);
        assertKmsException(staticMsg, staticHttpCode, noPrimaryKmsException,
                TenantSecurityErrorCodes.NO_PRIMARY_KMS_CONFIGURATION);

        ErrorResponse unknownTenantError = new ErrorResponse(
                TenantSecurityErrorCodes.UNKNOWN_TENANT_OR_NO_ACTIVE_KMS_CONFIGURATIONS.getCode(), staticMsg);
        TenantSecurityException unknownTenantException = unknownTenantError.toTenantSecurityException(staticHttpCode);
        assertKmsException(staticMsg, staticHttpCode, unknownTenantException,
                TenantSecurityErrorCodes.UNKNOWN_TENANT_OR_NO_ACTIVE_KMS_CONFIGURATIONS);

        ErrorResponse kmsCfgDisabledError = new ErrorResponse(
                TenantSecurityErrorCodes.KMS_CONFIGURATION_DISABLED.getCode(), staticMsg);
        TenantSecurityException kmsCfgDisabledException = kmsCfgDisabledError.toTenantSecurityException(staticHttpCode);
        assertKmsException(staticMsg, staticHttpCode, kmsCfgDisabledException,
                TenantSecurityErrorCodes.KMS_CONFIGURATION_DISABLED);

        ErrorResponse invalidEdekErrResp = new ErrorResponse(TenantSecurityErrorCodes.INVALID_PROVIDED_EDEK.getCode(),
                staticMsg);
        TenantSecurityException invalidEdekException = invalidEdekErrResp.toTenantSecurityException(staticHttpCode);
        assertKmsException(staticMsg, staticHttpCode, invalidEdekException,
                TenantSecurityErrorCodes.INVALID_PROVIDED_EDEK);

        ErrorResponse unwrapError = new ErrorResponse(TenantSecurityErrorCodes.KMS_UNWRAP_FAILED.getCode(), staticMsg);
        TenantSecurityException unwrapException = unwrapError.toTenantSecurityException(staticHttpCode);
        assertKmsException(staticMsg, staticHttpCode, unwrapException, TenantSecurityErrorCodes.KMS_UNWRAP_FAILED);

        ErrorResponse wrapError = new ErrorResponse(TenantSecurityErrorCodes.KMS_WRAP_FAILED.getCode(), staticMsg);
        TenantSecurityException kmsWrapException = wrapError.toTenantSecurityException(staticHttpCode);
        assertKmsException(staticMsg, staticHttpCode, kmsWrapException, TenantSecurityErrorCodes.KMS_WRAP_FAILED);

        ErrorResponse kmsAuthError = new ErrorResponse(TenantSecurityErrorCodes.KMS_AUTHORIZATION_FAILED.getCode(),
                staticMsg);
        TenantSecurityException kmsAuthException = kmsAuthError.toTenantSecurityException(staticHttpCode);
        assertKmsException(staticMsg, staticHttpCode, kmsAuthException,
                TenantSecurityErrorCodes.KMS_AUTHORIZATION_FAILED);

        ErrorResponse kmsConfigInvalidError = new ErrorResponse(
                TenantSecurityErrorCodes.KMS_CONFIGURATION_INVALID.getCode(), staticMsg);
        TenantSecurityException kmsConfigInvalidException = kmsConfigInvalidError
                .toTenantSecurityException(staticHttpCode);
        assertKmsException(staticMsg, staticHttpCode, kmsConfigInvalidException,
                TenantSecurityErrorCodes.KMS_CONFIGURATION_INVALID);

        ErrorResponse kmsUnreachableError = new ErrorResponse(TenantSecurityErrorCodes.KMS_UNREACHABLE.getCode(),
                staticMsg);
        TenantSecurityException kmsUnreachableException = kmsUnreachableError.toTenantSecurityException(staticHttpCode);
        assertKmsException(staticMsg, staticHttpCode, kmsUnreachableException,
                TenantSecurityErrorCodes.KMS_UNREACHABLE);

        // SecurityEventException
        ErrorResponse securityEventRejectedError = new ErrorResponse(
                TenantSecurityErrorCodes.SECURITY_EVENT_REJECTED.getCode(), staticMsg);
        TenantSecurityException securityEventRejectedException = securityEventRejectedError
                .toTenantSecurityException(staticHttpCode);
        assertSecurityEventException(staticMsg, staticHttpCode, securityEventRejectedException,
                TenantSecurityErrorCodes.SECURITY_EVENT_REJECTED);
    }

    private void assertTspServiceException(String expectedMsg, int expectedHttpStatusCode,
            TenantSecurityException exception, TenantSecurityErrorCodes errorCode) {
        assertTenantSecurityException(expectedMsg, expectedHttpStatusCode, exception, errorCode);
        assertTrue(exception instanceof TspServiceException);
    }

    private void assertSecurityEventException(String expectedMsg, int expectedHttpStatusCode,
            TenantSecurityException exception, TenantSecurityErrorCodes errorCode) {
        assertTenantSecurityException(expectedMsg, expectedHttpStatusCode, exception, errorCode);
        assertTrue(exception instanceof SecurityEventException);
    }

    private void assertKmsException(String expectedMsg, int expectedHttpStatusCode, TenantSecurityException exception,
            TenantSecurityErrorCodes errorCode) {
        assertTenantSecurityException(expectedMsg, expectedHttpStatusCode, exception, errorCode);
        assertTrue(exception instanceof KmsException);
    }

    private void assertTenantSecurityException(String expectedMsg, int expectedHttpStatusCode,
            TenantSecurityException exception, TenantSecurityErrorCodes errorCode) {
        assertEquals(errorCode, exception.getErrorCode());
        assertEquals(exception.getHttpResponseCode(), expectedHttpStatusCode);
        assertEquals(exception.getMessage(), expectedMsg);
    }

}