package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.FileReader;
import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

@Test(groups = {"unit"})
public class TenantSecurityRequestTest {

  public void testSdkVersion() throws Exception {
    MavenXpp3Reader reader = new MavenXpp3Reader();
    Model model = reader.read(new FileReader("pom.xml"));
    assertEquals(TenantSecurityRequest.sdkVersion, model.getVersion());
  }
}
