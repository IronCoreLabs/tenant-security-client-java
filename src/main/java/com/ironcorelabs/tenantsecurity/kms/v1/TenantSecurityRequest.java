package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.Closeable;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
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
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import com.google.api.client.http.json.JsonHttpContent;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TenantSecurityException;
import com.ironcorelabs.tenantsecurity.kms.v1.exception.TspServiceException;
import com.ironcorelabs.tenantsecurity.logdriver.v1.EventMetadata;
import com.ironcorelabs.tenantsecurity.logdriver.v1.SecurityEvent;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;

/**
 * Handles requests to the Tenant Security Proxy Docker image for wrapping and unwrapping keys. Also
 * works to parse out error codes on wrap/unwrap failures.
 */
final class TenantSecurityRequest implements Closeable {
    private static final JsonFactory JSON_FACTORY = new JacksonFactory();

    // Fixed sized thread pool for web requests. Limit the amount of parallel web
    // requests that we let go out at any given time. We don't want to DoS our
    // Tenant Security Proxy with too many requests at the same time. The size of
    // this thread pools is configurable on construction.
    private ExecutorService webRequestExecutor;

    private final HttpHeaders httpHeaders;
    private final GenericUrl wrapEndpoint;
    private final GenericUrl batchWrapEndpoint;
    private final GenericUrl unwrapEndpoint;
    private final GenericUrl batchUnwrapEndpoint;
    private final GenericUrl rekeyEndpoint;
    private final GenericUrl securityEventEndpoint;
    private final HttpRequestFactory requestFactory;
    private final int timeout;

    TenantSecurityRequest(String tspDomain, String apiKey, int requestThreadSize, int timeout) {
        HttpHeaders headers = new HttpHeaders();
        headers.put("Content-Type", "application/json");
        headers.put("Authorization", "cmk " + apiKey);
        this.httpHeaders = headers;

        String tspApiPrefix = tspDomain + "/api/1/";
        this.wrapEndpoint = new GenericUrl(tspApiPrefix + "document/wrap");
        this.batchWrapEndpoint = new GenericUrl(tspApiPrefix + "document/batch-wrap");
        this.unwrapEndpoint = new GenericUrl(tspApiPrefix + "document/unwrap");
        this.batchUnwrapEndpoint = new GenericUrl(tspApiPrefix + "document/batch-unwrap");
        this.rekeyEndpoint = new GenericUrl(tspApiPrefix + "document/rekey");
        this.securityEventEndpoint = new GenericUrl(tspApiPrefix + "event/security-event");

        this.webRequestExecutor = Executors.newFixedThreadPool(requestThreadSize);
        this.requestFactory = provideHttpRequestFactory(requestThreadSize, requestThreadSize);
        this.timeout = timeout;
    }

    public void close() throws IOException {
        this.webRequestExecutor.shutdown();
    }

    /**
     * Build up a generic HttpRequest which includes the appropriate headers to make requests to the
     * Tenant Security Proxy.
     */
    private HttpRequest getApiRequest(Map<String, Object> postData, GenericUrl endpoint) throws Exception {
        return requestFactory.buildPostRequest(endpoint, new JsonHttpContent(JSON_FACTORY, postData))
                // Clone the headers on use. Otherwise Google will keep appending their custom
                // user agent string and it will grow big enough to cause header overflow
                // errors.
                .setHeaders(this.httpHeaders.clone()).setReadTimeout(this.timeout).setConnectTimeout(this.timeout)
                // We want to parse out error codes, so don't throw when we get a non-200
                // response code
                .setThrowExceptionOnExecuteError(false);
    }

    /**
     * Attempt to convert a failed HTTP request to an error code that we can communicate out to
     * callers. Attempts to parse the response as JSON and convert the received error code over to
     * the type of failure that occurred.
     */
    private TenantSecurityException parseFailureFromRequest(HttpResponse resp) {
        if (resp.getStatusCode() == HttpStatusCodes.STATUS_CODE_UNAUTHORIZED) {
            // The Google client wont parse 401 response bodies. The only way we can get a 401
            // response is if the header
            // was wrong, so hardcode that result here
            return new TspServiceException(TenantSecurityErrorCodes.UNAUTHORIZED_REQUEST, resp.getStatusCode());
        }
        try {
            ErrorResponse errorResponse = resp.parseAs(ErrorResponse.class);
            return errorResponse.toTenantSecurityException(resp.getStatusCode());
        } catch (Exception e) {
            /* Fall through and return unknown error below */
        }
        return new TspServiceException(TenantSecurityErrorCodes.UNKNOWN_ERROR, resp.getStatusCode());
    }

    /**
     * Generic method for making a request to the provided URL with the provided post data. Returns
     * an instance of the provided generic JSON class or an error message with the provided error.
     */
    private <T> CompletableFuture<T> makeRequestAndParseFailure(GenericUrl url, Map<String, Object> postData,
            Class<T> jsonType, String errorMessage) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                HttpResponse resp = this.getApiRequest(postData, url).execute();
                if (resp.isSuccessStatusCode()) {
                    return resp.parseAs(jsonType);
                }
                throw parseFailureFromRequest(resp);
            } catch (Exception cause) {
                if (cause instanceof TenantSecurityException) {
                    throw new CompletionException(cause);
                }
                throw new CompletionException(new TspServiceException(TenantSecurityErrorCodes.UNABLE_TO_MAKE_REQUEST,
                        0, errorMessage, cause));
            }
        }, webRequestExecutor);
    }

    /**
     * Request wrap endpoint to generate a DEK and EDEK.
     */
    CompletableFuture<WrappedDocumentKey> wrapKey(DocumentMetadata metadata) {
        Map<String, Object> postData = metadata.getAsPostData();
        String error = String.format(
                "Unable to make request to Tenant Security Proxy wrap endpoint. Endpoint requested: %s",
                this.wrapEndpoint);
        return this.makeRequestAndParseFailure(this.wrapEndpoint, postData, WrappedDocumentKey.class, error);
    }

    /**
     * Request batch wrap endpoint to generate the provided number of DEK/EDEK pairs.
     */
    CompletableFuture<BatchWrappedDocumentKeys> batchWrapKeys(Collection<String> documentIds,
            DocumentMetadata metadata) {
        Map<String, Object> postData = metadata.getAsPostData();
        postData.put("documentIds", documentIds);
        String error = String.format(
                "Unable to make request to Tenant Security Proxy batch wrap endpoint. Endpoint requested: %s",
                this.batchWrapEndpoint);
        return this.makeRequestAndParseFailure(this.batchWrapEndpoint, postData, BatchWrappedDocumentKeys.class, error);
    }

    /**
     * Request unwrap endpoint with the provided edek. Returns the resulting DEK.
     */
    CompletableFuture<byte[]> unwrapKey(String edek, DocumentMetadata metadata) {
        Map<String, Object> postData = metadata.getAsPostData();
        postData.put("encryptedDocumentKey", edek);
        String error = String.format(
                "Unable to make request to Tenant Security Proxy unwrap endpoint. Endpoint requested: %s",
                this.unwrapEndpoint);
        return this.makeRequestAndParseFailure(this.unwrapEndpoint, postData, UnwrappedDocumentKey.class, error)
                .thenApply(unwrapResponse -> {
                    try {
                        return unwrapResponse.getDekBytes();
                    } catch (Exception e) {
                        throw new CompletionException(new TspServiceException(
                                TenantSecurityErrorCodes.UNABLE_TO_MAKE_REQUEST, 0, e.getMessage(), e));
                    }
                });
    }

    /**
     * Request batch unwrap endpoint with the provided map of edeks. Returns a map of EDEK key to
     * DEK for successes and a map of EDEK key to failure details for failures.
     */
    CompletableFuture<BatchUnwrappedDocumentKeys> batchUnwrapKeys(Map<String, String> edeks,
            DocumentMetadata metadata) {
        Map<String, Object> postData = metadata.getAsPostData();
        postData.put("edeks", edeks);
        String error = String.format(
                "Unable to make request to Tenant Security Proxy batch unwrap endpoint. Endpoint requested: %s",
                this.batchWrapEndpoint);
        return this.makeRequestAndParseFailure(this.batchUnwrapEndpoint, postData, BatchUnwrappedDocumentKeys.class,
                error);
    }

    /**
     * Request re-key endpoint to unwrap an EDEK encrypted to the metadata's tenantId and then wrap it to the newTenantId.
     */
    CompletableFuture<RekeyedDocumentKey> rekey(String edek, DocumentMetadata metadata, String newTenantId) {
        Map<String, Object> postData = metadata.getAsPostData();
        postData.put("encryptedDocumentKey", edek);
        postData.put("newTenantId", newTenantId);
        String error = String.format(
                "Unable to make request to Tenant Security Proxy rekey endpoint. Endpoint requested: %s",
                this.rekeyEndpoint);
        return this.makeRequestAndParseFailure(this.rekeyEndpoint, postData, RekeyedDocumentKey.class, error);
    }

    /**
     * Request to the security event endpoint with the provided event and metadata.
     * 
     * @param event    Security event representing the action to be logged.
     * @param metadata Metadata associated with the security event.
     * @return Void on success. Failures come back as exceptions
     */
    CompletableFuture<Void> logSecurityEvent(SecurityEvent event, EventMetadata metadata) {
        Map<String, Object> postData = combinePostableEventAndMetadata(event, metadata);
        String error = String.format(
                "Unable to make request to Tenant Security Proxy security event endpoint. Endpoint requested: %s",
                this.securityEventEndpoint);
        return this.makeRequestAndParseFailure(this.securityEventEndpoint, postData, Void.class, error);
    }

    private Map<String, Object> combinePostableEventAndMetadata(SecurityEvent event, EventMetadata metadata) {
        Map<String, Object> postData = metadata.getAsPostData();
        // Add the object of this call, the event, to the post data that's ready to go out.
        // We just created this, so we know the cast is safe. There is a unit case to catch this in
        // case it changes.
        Map<String, Object> iclFields = (HashMap<String, Object>) postData.get("iclFields");
        iclFields.put("event", event.getFlatEvent());
        postData.put("iclFields", iclFields);
        return postData;
    }

    /**
     * Create the factory for http requests. The main reason for this is to provide connection
     * pooling for situations where large numbers of requests are desired.
     *
     * @param maxConnections      global max connections
     * @param maxRouteConnections max connections for a single HTTP endpoint
     * @return HttpRequestFactory with connection pooling enabled.
     */
    static HttpRequestFactory provideHttpRequestFactory(int maxConnections, int maxRouteConnections) {
        final PoolingHttpClientConnectionManager cm = new PoolingHttpClientConnectionManager();
        // Increase max total connections
        cm.setMaxTotal(maxConnections);
        // Increase default max connection per route
        cm.setDefaultMaxPerRoute(maxRouteConnections);

        final CloseableHttpClient httpClient = HttpClients.createMinimal(cm);
        final HttpTransport httpTransport = new ApacheHttpTransport(httpClient);

        return httpTransport.createRequestFactory((HttpRequest request) -> {
            request.setParser(new JsonObjectParser(JSON_FACTORY));
        });
    }
}
