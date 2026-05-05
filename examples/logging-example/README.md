# Logging Example

In order to run this example, you need to be running a _Tenant Security Proxy_ (TSP) on your machine.
Check the [README.md](../README.md) file in the parent directory to see how to start the TSP, if you haven't done so
yet.

Once the TSP is running, you can experiment with this example Java program. It illustrates the basics of how
to use the Tenant Security Client (TSC) SDK to log security events. The example code shows two scenarios:

- logging a user create security event with minimal metadata
- logging a login security event with additional metadata

To run the example, you will need to have Java JRE 17+ and Maven installed on your computer.

If java is ready to go, execute these commands:

```bash
export API_KEY='0WUaXesNgbTAuLwn'
mvn package
java -cp target/logging-example-0.1.0.jar com.ironcorelabs.logging.LoggingExample
```

We've assigned an API key for you, but in production you will make your own and edit the TSP
configuration with it. This should produce output like:

```bash
λ java -cp target/logging-example-0.1.0.jar com.ironcorelabs.logging.LoggingExample
Using tenant tenant-gcp-l
Successfully logged user login event.
Successfully logged admin add event.
```

The output "Successfully logged user login event." is printed after successfully sending the login event
to the TSP. Same thing with "Successfully logged admin add event." but for the add event.

If you look in the TSP logs you should see something like:

```
tenant-security-proxy-1      | {"contexts":"request","level":"INFO","service":"proxy","timestamp":"2026-05-05T17:36:45.634142Z","message":"Security Event Received","name":"request","ray_id":"7kxICOonlsf0Yb_a","tenant_id":"tenant-gcp-l"}
tenant-security-proxy-1      | {"contexts":"request","level":"INFO","service":"proxy","timestamp":"2026-05-05T17:36:45.634169Z","message":"{\"iclFields\":{\"dataLabel\":\"PII\",\"requestId\":\"Rq8675309\",\"requestingId\":\"userId1\",\"sourceIp\":\"127.0.0.1\",\"objectId\":\"userId1\",\"event\":\"USER_LOGIN\"},\"customFields\":{\"field2\":\"gumby\",\"field1\":\"gumby\"}}","name":"request","ray_id":"7kxICOonlsf0Yb_a","tenant_id":"tenant-gcp-l"}
tenant-security-proxy-1      | {"contexts":"request","level":"INFO","service":"proxy","timestamp":"2026-05-05T17:36:45.642246Z","message":"Security Event Received","name":"request","ray_id":"hWR9meUHd3j5_n3Z","tenant_id":"tenant-gcp-l"}
tenant-security-proxy-1      | {"contexts":"request","level":"INFO","service":"proxy","timestamp":"2026-05-05T17:36:45.642269Z","message":"{\"iclFields\":{\"dataLabel\":\"PII\",\"requestId\":null,\"requestingId\":\"adminId1\",\"sourceIp\":null,\"objectId\":null,\"event\":\"USER_ADD\"},\"customFields\":{}}","name":"request","ray_id":"hWR9meUHd3j5_n3Z","tenant_id":"tenant-gcp-l"}
tenant-security-logdriver-1  | {"contexts":"main;batching;tenant","level":"INFO","service":"logdriver","timestamp":"2026-05-05T17:36:47.663634676Z","message":"BATCH: 2 log events received for an unknown tenant. Using a stdout logger for this tenant.","name":"tenant","tenant_id":"tenant-gcp-l"}
tenant-security-logdriver-1  | {"contexts":"main;batching;stdout client;write-entries","level":"INFO","service":"logdriver","timestamp":"2026-05-05T17:36:47.663797301Z","message":"{\"tenantId\":\"tenant-gcp-l\",\"timestamp\":\"2026-05-05T17:36:45.576Z\",\"iclFields\":{\"logdriverRayId\":\"bAZjbUAXfSkTfOwh\",\"event\":\"USER_LOGIN\",\"requestingId\":\"userId1\",\"dataLabel\":\"PII\",\"objectId\":\"userId1\",\"requestId\":\"Rq8675309\",\"sourceIp\":\"127.0.0.1\",\"tspRayId\":\"ray_id\"},\"customFields\":{\"field2\":\"gumby\",\"field1\":\"gumby\"}}","name":"write-entries"}
tenant-security-logdriver-1  | {"contexts":"main;batching;stdout client;write-entries","level":"INFO","service":"logdriver","timestamp":"2026-05-05T17:36:47.663823051Z","message":"{\"tenantId\":\"tenant-gcp-l\",\"timestamp\":\"2026-05-05T17:36:45.640Z\",\"iclFields\":{\"event\":\"USER_ADD\",\"dataLabel\":\"PII\",\"logdriverRayId\":\"wGC7kDMkGf-1l0uo\",\"requestingId\":\"adminId1\",\"tspRayId\":\"ray_id\"},\"customFields\":{}}","name":"write-entries"}
```

This shows the TSP receiving these events, batching them up together, and sending them successfully to Logdriver. Because this tenant does not have a log sink configured,
the security events will be output to Logdriver's stdout logs.

If you would like to experiment with a different tenant, just do:

```bash
export TENANT_ID=<selected-tenant-ID>
java -cp target/logging-example-0.1.0.jar com.ironcorelabs.logging.LoggingExample
```

The list of available tenants is listed in the **README.md** in the parent directory.

## Additional Resources

If you would like some more in-depth information, our website features a section of technical
documentation about the [SaaS Shield product](https://ironcorelabs.com/docs/saas-shield/).
