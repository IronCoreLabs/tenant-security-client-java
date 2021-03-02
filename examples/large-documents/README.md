# Large Documents

In order to run this example, you need to be running a _Tenant Security Proxy_ (TSP) on your machine.
Check the **README.md** file in the parent directory to see how to start the TSP, if you haven't done so
yet.

Once the TSP is running, you can experiment with this example Java program. It illustrates the basics of how
to use the Tenant Security Client (TSC) SDK to performantly encrypt/decrypt large documents or a set of many
fields that share a DEK. The example code shows two scenarios:

- encrypting a large document as many subdocs, using the disk for persistence
- retrieving and decrypting subdocs individually

To run the example, you will need to have Java and Maven installed on your computer. Try a `java -version` to see
what version you are using. We tested the example code using 1.8.

If java is ready to go, execute these commands:

```bash
export API_KEY='0WUaXesNgbTAuLwn'
mvn package
java -cp target/large-documents-example-0.1.0.jar com.ironcorelabs.large.LargeDocuments
```

We've assigned an API key for you, but in production you will make your own and edit the TSP
configuration with it. This should produce output like:

```bash
λ java -cp target/large-documents-example-0.1.0.jar com.ironcorelabs.large.LargeDocuments
Using tenant tenant-azure-l
Writing encrypted files to: /tmp/saas-shield566835192357707822
```

The output "Writing encrypted files to:" is printed after successfully encrypting files using a key from the TSP.
If you inspect that folder you'll see many encrypted documents and a single edek that was used to encrypt all of them.

If you look in the TSP logs you should see output with information about calls to the KMS for that tenant.

If you would like to experiment with a different tenant, just do:

```bash
export TENANT_ID=<selected-tenant-ID>
java -cp target/large-documents-example-0.1.0.jar com.ironcorelabs.large.LargeDocuments
```

The list of available tenants is listed in the **README.md** in the parent directory.

## Additional Resources

If you would like some more in-depth information, our website features a section of technical
documentation about the [SaaS Shield product](https://ironcorelabs.com/docs/saas-shield/).
