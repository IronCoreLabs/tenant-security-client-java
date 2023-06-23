# Contributing to Tenant Security Client Java Library

## Formatting

We format the Java files in this repo using the `formatter-config.xml` Eclipse configuration for google-java-format. You can run formatting with `mvn formatter:format` and verify it with `mvn formatter:validate`. CI will ensure that all files are formatted properly before passing.

If you are using the `redhat.java` extension for VSCode, you can set `"java.format.settings.url": "{PATH-TO-TSC-JAVA}/formatter-config.xml"` for this workspace to ensure consistent formatting.

## Running a Tenant Security Proxy

See our [TSP documentation](https://ironcorelabs.com/docs/customer-managed-keys/tenant-security-proxy/overview) for information about how to get your own TSP running to test against. The tests will expect the TSP to be running at `http://localhost:7777`.

## Tests

This client has both a set of unit tests as well as several integration test suites. Because of the complexity of the various services required to run non-unit test suites, these tests have a lot more setup required which is explained below.

### Unit Tests

Tests that check functionality that is contained within the client.

- Run `test-suites/unitTest.sh`.

### Local Development Integration Tests

These tests are meant for local developers to be able to do a full end-to-end test from the client all the way through to the Config Broker. This test will perform a full round-trip encryption and decryption and verify that the data is successfully decrypted to its original value. This test assumes that you've done the work of setting up the Tenant Security Proxy from above as well as setting up the associated Config Broker vendor account with a tenant and a KMS config. Open the [`LocalRoundTrip.java`](src/test/java/com/ironcorelabs/tenantsecurity/kms/v1/LocalRoundTrip.java) file and set the values for your `TENANT_ID` and `API_KEY` within the test class. To run tests over the batch functions, do the same for [`LocalBatch.java`](src/test/java/com/ironcorelabs/tenantsecurity/kms/v1/LocalBatch.java).

Once complete, perform the following steps

- Start up the Tenant Security Proxy.
- Run `test-suites/localTest.sh` to run the local roundtrip test.
- Run `test-suites/localBatchTest.sh` to run local roundtrip tests using the batch functions.

### Complete Integration Tests

We've created a number of accounts within a Config Broker dev environment that have tenants set up for all the different KMS types that we support. This allows us to run a more complete suite of integration tests that exercise more parts of both the client as well as the Tenant Security Proxy. These tests are not runnable by the public. You can view the results of these test runs in [CI](https://github.com/IronCoreLabs/tenant-security-client-java/actions).

### CI Automated Tests

The CI job runs tests using the [tenant-security-proxy](https://github.com/IronCoreLabs/tenant-security-proxy) repo.
If your tests don't build against the default branch of that repo, you can change it by adding a command to the pull request. The
comment should contain the string `CI_branches` and a JSON object like
`{"tenant-security-proxy": "some_branch"}`. You can include formatting, prose, or a haiku,
but no `{` or `}` characters. Example:

```
CI_branches: `{"tenant-security-proxy": "some_branch"}`

This new branch needs to build against some_branch.
```
