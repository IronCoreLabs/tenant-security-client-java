package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.StringReader;
import org.testng.annotations.Test;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.gson.GsonFactory;

@Test(groups = {"unit"})
public class JsonParsingTest {
  static JsonObjectParser parser = new JsonObjectParser(new GsonFactory());

  @Test(expectedExceptions = IllegalArgumentException.class)
  void batchKeysAreEmpty() throws Exception {
    String json = "{}";
    BatchWrappedDocumentKeys type = parser.<BatchWrappedDocumentKeys>parseAndClose(
        new StringReader(json), BatchWrappedDocumentKeys.class);
    type.ensureNoNullsOrThrow();
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  void derivedKeyResponseIsEmpty() throws Exception {
    String json = "{}";
    DeriveKeyResponse type =
        parser.<DeriveKeyResponse>parseAndClose(new StringReader(json), DeriveKeyResponse.class);
    type.ensureNoNullsOrThrow();

  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  void unwrappedDocumentKeyErrors() throws Exception {
    String json = "{}";
    UnwrappedDocumentKey type = parser.<UnwrappedDocumentKey>parseAndClose(new StringReader(json),
        UnwrappedDocumentKey.class);
    type.ensureNoNullsOrThrow();
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  void wrappedDocumentKeyErrors() throws Exception {
    String json = "{}";
    WrappedDocumentKey type =
        parser.<WrappedDocumentKey>parseAndClose(new StringReader(json), WrappedDocumentKey.class);
    type.ensureNoNullsOrThrow();
  }

  @Test(expectedExceptions = IllegalArgumentException.class)
  void rekeyedDocumentKeyIsNull() throws Exception {
    String json = "{}";
    RekeyedDocumentKey type =
        parser.<RekeyedDocumentKey>parseAndClose(new StringReader(json), RekeyedDocumentKey.class);
    type.ensureNoNullsOrThrow();
  }
}
