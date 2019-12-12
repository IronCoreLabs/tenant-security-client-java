# Tenant Security Client Java Library

A Java client for implementing CMK within a vendors infrastructure. Makes requests through an
IronCore Tenant Security Proxy to tenants' KMS/logging infrastructures.

More extensive documentation about usage is available on our [docs site](https://ironcorelabs.com/docs/customer-managed-keys/tenant-security-client/overview).

## Running a Tenant Security Proxy

See our [TSP documentation](https://ironcorelabs.com/docs/customer-managed-keys/tenant-security-proxy/overview) for information about how to get your own TSP running to test against.

## Tests

This client has both a set of unit tests as well as several integration test suites. Because of the complexity of the various services requried to run non-unit test suites, these tests have a lot more setup requried which is explained below.

#### Unit Tests

Tests that check functionality that is contained within the client.

- Run `test-suites/unitTest.sh`.

#### Local Development Integration Tests

These tests are meant for local devlopers to be able to do a full end-to-end test from the client all the way through to the Config Broker. This test will perform a full round-trip encryption and decryption and verify that the data is successfully decrypted to it's original value. This test assumes that you've done the work of setting up the Tenant Security Proxy from above as well as setting up the associated Config Broker vendor account with a tenant and a KMS config. Open the [`LocalRoundTrip.java`](src/test/java/com/ironcorelabs/tenantsecurity/kms/v1/LocalRoundTrip.java) file and set the values for your `TENANT_ID` and `API_KEY` within the test class.

Once complete, perform the following steps

- Start up the Tenant Security Proxy
- Run `test-suites/localTest.sh` to kick off the test.

#### Complete Integration Tests

We've created a number of accounts within a Config Broker dev enviroment that have tenants set up for all the different KMS types that we support. This allows us to run a more complete suite of integration tests that exercise more parts of both the client as well as the Tenant Security Proxy. These tests are not runnable by the public. You can view the results of these test runs in [CI](https://github.com/IronCoreLabs/tenant-security-client-java/actions).

## Deploy

We deploy the SDK to [Maven Central](https://search.maven.org/artifact/com.ironcorelabs/tenant-security-java/).

- You'll need to be authenticated and associated to our IronCore Sonatype account.
- Run `mvn clean source:jar javadoc:jar deploy`.

## License

The Tenant Security Client is licensed under the [GNU Affero General Public License](https://github.com/IronCoreLabs/ironoxide/blob/master/LICENSE). We also offer commercial licenses - [email](mailto:info@ironcorelabs.com) for more information.

Copyright (c) 2019 IronCore Labs, Inc. All rights reserved.
