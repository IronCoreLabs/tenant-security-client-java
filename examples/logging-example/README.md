# Logging Example

In order to run this example, you need to be running a _Tenant Security Proxy_ (TSP) on your machine.
Check the [README.md](../README.md) file in the parent directory to see how to start the TSP, if you haven't done so
yet.

Once the TSP is running, you can experiment with this example Java program. It illustrates the basics of how
to use the Tenant Security Client (TSC) SDK to log security events. The example code shows two scenarios:

- logging a user create security event with minimal metadata
- logging a login security event with additional metadata

To run the example, you will need to have Java and Maven installed on your computer. Try a `java -version` to see
what version you are using. We tested the example code using 1.8.

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

```bash
{"service":"proxy","message":"Security Event Received","level":"INFO","timestamp":"2021-02-16T17:45:57.968113921+00:00","tenant_id":"tenant-gcp-l","rayid":"0cddK3H_8SPxGr_t"}
{"service":"proxy","message":"{\"iclFields\":{\"dataLabel\":\"PII\",\"requestId\":\"Rq8675309\",\"requestingId\":\"userId1\",\"sourceIp\":\"127.0.0.1\",\"objectId\":\"userId1\",\"event\":\"USER_LOGIN\"},\"customFields\":{\"field2\":\"gumby\",\"field1\":\"gumby\"}}","level":"INFO","timestamp":"2021-02-16T17:45:57.968137530+00:00","tenant_id":"tenant-gcp-l","rayid":"0cddK3H_8SPxGr_t"}
{"service":"proxy","message":"Security Event Received","level":"INFO","timestamp":"2021-02-16T17:45:57.984058493+00:00","tenant_id":"tenant-gcp-l","rayid":"ScNfti6R0JMZlTQ6"}
{"service":"proxy","message":"{\"iclFields\":{\"dataLabel\":\"PII\",\"requestId\":null,\"requestingId\":\"adminId1\",\"sourceIp\":null,\"objectId\":null,\"event\":\"USER_ADD\"},\"customFields\":{}}","level":"INFO","timestamp":"2021-02-16T17:45:57.984083531+00:00","tenant_id":"tenant-gcp-l","rayid":"ScNfti6R0JMZlTQ6"}
{"service":"logdriver","message":"Making request to Stackdriver to write 2 log entries.","level":"INFO","timestamp":"2021-02-16T17:45:58.867370365+00:00","tenant_id":"tenant-gcp-l"}
{"service":"logdriver","message":"Successfully wrote 2 log entries to Stackdriver.","level":"INFO","timestamp":"2021-02-16T17:45:59.047270024+00:00","tenant_id":"tenant-gcp-l"}
```

This shows the TSP receiving these events, batching them up together, and sending them successfully to Stackdriver (the configured log sink for
`tenant-gcp-l`).

If you would like to experiment with a different tenant, just do:

```bash
export TENANT_ID=<selected-tenant-ID>
java -cp target/logging-example-0.1.0.jar com.ironcorelabs.logging.LoggingExample
```

The list of available tenants is listed in the **README.md** in the parent directory.

## Additional Resources

If you would like some more in-depth information, our website features a section of technical
documentation about the [SaaS Shield product](https://ironcorelabs.com/docs/saas-shield/).
