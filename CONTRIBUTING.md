# Contributing to Tenant Security Client Java Library

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

- You'll need to be authenticated and associated to our IronCore Sonatype account. This requires a user name and password for the
`sonatype-nexus` server to be stored in your `.m2/settings.xml` file. The user name and password we use for releasing are stored
on Drive in `IT_Info/sonatype-info.txt.iron`.
- You'll also need a GPG signing key to sign the release. Decrypt `IT_Info/pgp/rsa-signing-subkey.asc.iron`, then
`gpg --import rsa_signing_key.asc`.
- Update the `<version>` in `pom.xml`.
- Run `mvn clean source:jar javadoc:jar deploy -Dsuite=test-suites/test-unit` to deploy the release to Maven Central.
**NOTE**: this command will need the passphrase associated with the GPG signing key.
If that hasn't been entered recently, the command will error with a "signing failed" message.
You need to do a signing operation like `gpg -s pom.xml`, then enter the passphrase for the key.
After that, re-run the `mvn` commmand.
- When the artifacts have been deployed, you need to go to `https://oss.sonatype.org`, log in using the `icl-devops` username and
password, and find the new release in the *Staging Repositories*. You must close that repository and then release it in order to
actually push the package out to the public repo.


This is a sample `settings.xml` file for `maven`:
```
<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.0.0 https://maven.apache.org/xsd/settings-1.0.0.xsd">
  <localRepository>${user.home}/.m2/repository</localRepository>
  <servers>
    <server>
      <id>sonatype-nexus</id>
      <username>icl-devops</username>
      <password>***************************</password>
    </server>
  </servers>
</settings>
```

