# Cached Key Example

In order to run this example, you need to be running a _Tenant Security Proxy_ (TSP) on your machine.
Check the [README.md](../README.md) file in the parent directory to see how to start the TSP, if you haven't done so
yet.

Once the TSP is running, you can experiment with this example Java program. It demonstrates using
`CachedEncryptor` and `CachedDecryptor` to encrypt and decrypt multiple records while minimizing
calls to the TSP. The example code shows two scenarios:

- encrypting three of a customer's records using a single cached key (one TSP wrap call)
- decrypting all three records using a single cached key (one TSP unwrap call)

## Why use a cached key?

A normal `encrypt()` call wraps a new DEK through the TSP on every invocation. If you're encrypting
several records in quick succession (like inside a database transaction), each call
adds a network round trip.

A `CachedEncryptor` wraps the DEK once, then all subsequent `encrypt()` calls are purely local
CPU work. This means you can safely encrypt inside a database transaction without adding network
latency or external failure modes to the transaction. The same applies to `CachedDecryptor` for
reads.

## Running the example

To run the example, you will need to have a Java JRE 17+ and Maven installed on your computer.

```bash
export API_KEY='0WUaXesNgbTAuLwn'
mvn package
java -cp target/cached-key-example-0.1.0.jar com.ironcorelabs.cachedkey.CachedKeyExample
```

We've assigned an API key for you, but in production you will make your own and edit the TSP
configuration with it. This should produce output like:

```
Using tenant tenant-gcp-l
Encrypted 3 records with one TSP call
Decrypted: Jim Bridger / 000-12-2345
Decrypted: John Colter / 000-45-6789
Decrypted: Sacagawea / 000-98-7654
Decrypted 3 records with one TSP call
```

If you look at the TSP logs, you should see only two KMS operations: one wrap and one unwrap.
Without cached keys, the same work would have required six KMS operations (three wraps + three
unwraps).

If you would like to experiment with a different tenant, just do:

```bash
export TENANT_ID=<selected-tenant-ID>
java -cp target/cached-key-example-0.1.0.jar com.ironcorelabs.cachedkey.CachedKeyExample
```

The list of available tenants is listed in the [README.md](../README.md) in the parent directory.

## Additional Resources

If you would like some more in-depth information, our website features a section of technical
documentation about the [SaaS Shield product](https://ironcorelabs.com/docs/saas-shield/).
