# Releasing

We deploy the SDK to [Maven Central](https://search.maven.org/artifact/com.ironcorelabs/tenant-security-java/).

- Update the `<version>` in [pom.xml](./pom.xml).
- Put the username and password for the `icl-devops` Sonatype account into your `.m2/settings.xml` file. These credentials are stored on Drive in `IT_Info/sonatype-info.txt.iron`. A sample of this file is given below.
- Import the GPG signing key needed to sign the release. In Google Drive, navigate to the `IT_Info/pgp` folder, download `rsa-signing-subkey.asc.iron` and `ops-info.txt.iron`, and decrypt them using IronHide. Then do the following:
  1. Copy the master password from `ops-info.txt` to your clipboard so it can be provided in step 3 when importing the secret key.
  2. `gpg --keyserver keys.gnupg.net --receive-keys 62F57B1B87928CAC`
  3. `gpg --import rsa-signing-subkey.asc`
- Run `mvn clean source:jar javadoc:jar deploy -Dsuite=test-suites/test-unit` to deploy the release to Maven Central.
  **NOTE**: this command will need the master password associated with the GPG signing key.
  If this hasn't been entered recently, the command may error with a `signing failed` message.
  You will need to do a signing operation like `gpg -s -u 62F57B1B87928CAC pom.xml` and then enter the master password for the key (`pom.xml.gpg` can then be deleted).
  After that, re-run the `mvn` command above.
  - To test the release process or to install `tenant-security-client-java` to your local machine, you can instead run
    `mvn clean source:jar javadoc:jar install -Dsuite=test-suites/test-unit` and verify that all steps of the
    release process complete successfully.
- When the artifacts have been deployed, go to https://oss.sonatype.org, log in using the `icl-devops` username and
  password from `sonatype-info.txt`, and find the new release in the _Staging Repositories_. Close that repository and then release it in order to actually push the package out to the public repo.

### Sample .m2/settings.xml

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
