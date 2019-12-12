package com.ironcorelabs.tenantsecurity.kms.v1;

import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpHeaders;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpStatusCodes;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;

/**
 * Handles requests to the Tenant Security Proxy Docker image for wrapping and
 * unwrapping keys. Also works to parse out error codes on wrap/unwrap failures.
 */
public final class TenantSecurityKMSRequest {
    private static final HttpTransport HTTP_TRANSPORT = new NetHttpTransport();
    private static final JsonFactory JSON_FACTORY = new JacksonFactory();
    private static HttpRequestFactory requestFactory = HTTP_TRANSPORT.createRequestFactory((HttpRequest request) -> {
        request.setParser(new JsonObjectParser(JSON_FACTORY));
    });

    // Fixed sized thread pool for web requests. Limit the amount of parallel web
    // requests that we let go out at any given time. We don't want to DoS our
    // Tenant Security Proxy with too many requests at the same time. The size of
    // this thread pools is configurable on construction.
    private ExecutorService webRequestExecutor;

    private final HttpHeaders httpHeaders;
    private final GenericUrl wrapEndpoint;
    private final GenericUrl unwrapEndpoint;

    public TenantSecurityKMSRequest(String tspDomain, String apiKey, int requestThreadSize) {
        HttpHeaders headers = new HttpHeaders();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", "cmk " + apiKey);
        this.httpHeaders = headers;

        String tspApiPrefix = tspDomain + "/api/1/";
        this.wrapEndpoint = new GenericUrl(tspApiPrefix + "document/wrap");
        this.unwrapEndpoint = new GenericUrl(tspApiPrefix + "document/unwrap");

        this.webRequestExecutor = Executors.newFixedThreadPool(requestThreadSize);
    }

    /**
     * Build up a generic HttpRequest which includes the appropriate headers to make
     * requests to the Tenant Security Proxy.
     */
    private HttpRequest getApiRequest(Map<String, Object> postData, GenericUrl endpoint) throws Exception {
        return requestFactory.buildPostRequest(endpoint, new JsonHttpContent(JSON_FACTORY, postData))
                // Clone the headers on use. Otherwise Google will keep appending their custom
                // user agent string and it will grow big enough to cause header overflow
                // errors.
                .setHeaders(this.httpHeaders.clone())
                // We want to parse out error codes, so don't throw when we get a non-200
                // response code
                .setThrowExceptionOnExecuteError(false);
    }

    /**
     * Attempt to convert a failed HTTP request to an error code that we can
     * communicate out to callers. Attempts to parse the response as JSON and
     * convert the received error code over to the type of failure that occured.
     */
    private TenantSecurityKMSException parseFailureFromRequest(HttpResponse resp) {
        if(resp.getStatusCode() == HttpStatusCodes.STATUS_CODE_UNAUTHORIZED){
            //The Google client wont parse 401 response bodies. The only way we can get a 401 response is if the header
            //was wrong, so hardcode that result here
            return new TenantSecurityKMSException(TenantSecurityKMSErrorCodes.UNAUTHORIZED_REQUEST, resp.getStatusCode());
        }
        try {
            ErrorResponse errorResponse = resp.parseAs(ErrorResponse.class);
            if (errorResponse.getCode() > 0 && TenantSecurityKMSErrorCodes.valueOf(errorResponse.getCode()) != null) {
                return new TenantSecurityKMSException(TenantSecurityKMSErrorCodes.valueOf(errorResponse.getCode()),
                        errorResponse.getMessage(), resp.getStatusCode());
            }
        } catch (Exception e) {
            /* Fall through and return unknown error below */}
        return new TenantSecurityKMSException(TenantSecurityKMSErrorCodes.UNKNOWN_ERROR, resp.getStatusCode());
    }

    /**
     * Request wrap endpoint to generate a DEK and EDEK.
     */
    public CompletableFuture<WrappedDocumentKey> wrapKey(DocumentMetadata metadata) {
        Map<String, Object> postData = metadata.getAsPostData();
        return CompletableFuture.supplyAsync(() -> {
            try {
                HttpResponse resp = this.getApiRequest(postData, this.wrapEndpoint).execute();
                if (resp.isSuccessStatusCode()) {
                    return resp.parseAs(WrappedDocumentKey.class);
                }
                throw parseFailureFromRequest(resp);
            } catch (Exception e) {
                if (e instanceof TenantSecurityKMSException) {
                    throw new CompletionException(e);
                }
                throw new CompletionException(new TenantSecurityKMSException(
                        TenantSecurityKMSErrorCodes.UNABLE_TO_MAKE_REQUEST,
                        String.format(
                                "Unable to make request to Tenant Security Proxy wrap endpoint. Endpoint requested: %s Error: %s",
                                this.wrapEndpoint, e),
                        0));
            }
        }, webRequestExecutor);
    }

    /**
     * Request unwrap endpoint with the provided edek. Returns the resulting DEK.
     */
    public CompletableFuture<byte[]> unwrapKey(String edek, DocumentMetadata metadata) {
        Map<String, Object> postData = metadata.getAsPostData();
        postData.put("encryptedDocumentKey", edek);
        return CompletableFuture.supplyAsync(() -> {
            try {
                HttpResponse resp = this.getApiRequest(postData, this.unwrapEndpoint).execute();
                if (resp.isSuccessStatusCode()) {
                    return resp.parseAs(UnwrappedDocumentKey.class).getDekBytes();
                }
                throw parseFailureFromRequest(resp);
            } catch (Exception e) {
                if (e instanceof TenantSecurityKMSException) {
                    throw new CompletionException(e);
                }
                throw new CompletionException(new TenantSecurityKMSException(
                        TenantSecurityKMSErrorCodes.UNABLE_TO_MAKE_REQUEST,
                        String.format(
                                "Unable to make request to Tenant Security Proxy unwrap endpoint. Endpoint requested: %s Error: %s",
                                this.wrapEndpoint, e),
                        0));
            }
        }, webRequestExecutor);
    }
}