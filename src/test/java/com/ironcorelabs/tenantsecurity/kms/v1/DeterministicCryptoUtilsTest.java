package com.ironcorelabs.tenantsecurity.kms.v1;

import static org.testng.Assert.assertEquals;

import java.security.SecureRandom;
import org.testng.annotations.Test;

@Test(groups = {"unit"})
public class DeterministicCryptoUtilsTest {
  DeterministicPlaintextField plaintextField =
      new DeterministicPlaintextField("aaaaaa".getBytes(), "deriv", "secret");
  DerivedKey[] derivedKeys = {new DerivedKey(
      "g2K8P7zoxO+yi4oDcR5Bk4grNuHFUBgqJ2Jgbh2bJzDk2Z/z8ji5WvF8aO2n/iUBl8tbKiaIs2n7R9vIBrXGmg==", 5,
      true),
      new DerivedKey(
          "AUvYQZVvGpqalGZyO7Sy5WSsJ9KqOkwP/jlQnvORy/hZVU1pTCLefEPKJ4mShUfdKOKbECMpuf7YpR9+CNwuEQ==",
          6, false)};
  // Same as `derivedKeys` but swapped `current`
  DerivedKey[] newDerivedKeys = {new DerivedKey(
      "g2K8P7zoxO+yi4oDcR5Bk4grNuHFUBgqJ2Jgbh2bJzDk2Z/z8ji5WvF8aO2n/iUBl8tbKiaIs2n7R9vIBrXGmg==", 5,
      false),
      new DerivedKey(
          "AUvYQZVvGpqalGZyO7Sy5WSsJ9KqOkwP/jlQnvORy/hZVU1pTCLefEPKJ4mShUfdKOKbECMpuf7YpR9+CNwuEQ==",
          6, true)};
  // Truly random, uses the underlying OS to decide what RNG you get.
  SecureRandom secureRandom = new SecureRandom();
  DocumentMetadata metadata =
      new DocumentMetadata("tenantId", "requestingUserOrServiceId", "dataLabel");


  private void assertEqualBytes(byte[] one, byte[] two) throws Exception {
    assertEquals(new String(one, "UTF-8"), new String(two, "UTF-8"));
  }

  // Values from Deterministic Authenticated Encryption Example at
  // https://datatracker.ietf.org/doc/html/rfc5297#appendix-A.1
  public void roundtripKnownBytes() throws Exception {
    byte[] key = CryptoUtilsTest
        .hexStringToByteArray("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    byte[] associatedData =
        CryptoUtilsTest.hexStringToByteArray("101112131415161718191a1b1c1d1e1f2021222324252627");
    byte[] plaintext = CryptoUtilsTest.hexStringToByteArray("112233445566778899aabbccddee");
    byte[] encrypted = DeterministicCryptoUtils.encryptBytes(plaintext, key, associatedData).get();
    byte[] expected = CryptoUtilsTest
        .hexStringToByteArray("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c");
    assertEquals(encrypted, expected);
    byte[] decrypted = DeterministicCryptoUtils.decryptBytes(encrypted, key, associatedData).get();
    assertEqualBytes(decrypted, plaintext);
  }

  public void encryptFieldRoundtrip() throws Exception {
    DeterministicEncryptedField encrypted =
        DeterministicCryptoUtils.encryptField(plaintextField, derivedKeys).get();
    DeterministicEncryptedField encrypted2 =
        DeterministicCryptoUtils.encryptField(plaintextField, derivedKeys).get();
    // encryption should be stable
    assertEqualBytes(encrypted.getEncryptedField(), encrypted2.getEncryptedField());
    DeterministicPlaintextField decrypted =
        DeterministicCryptoUtils.decryptField(encrypted, derivedKeys).get();
    assertEqualBytes(plaintextField.getPlaintextField(), decrypted.getPlaintextField());
  }

  @Test(expectedExceptions = java.util.concurrent.ExecutionException.class,
      expectedExceptionsMessageRegExp = ".*No current.*")
  public void encryptFailsWithNoCurrent() throws Exception {
    DerivedKey[] noCurrentDerivedKeys = {new DerivedKey(
        "AUvYQZVvGpqalGZyO7Sy5WSsJ9KqOkwP/jlQnvORy/hZVU1pTCLefEPKJ4mShUfdKOKbECMpuf7YpR9+CNwuEQ==",
        6, false)};
    DeterministicCryptoUtils.encryptField(plaintextField, noCurrentDerivedKeys).get();
  }

  @Test(expectedExceptions = java.util.concurrent.ExecutionException.class,
      expectedExceptionsMessageRegExp = ".*not valid base64.*")
  public void encryptFailsWithInvalidBase64() throws Exception {
    DerivedKey[] noCurrentDerivedKeys = {new DerivedKey("!!!!!!", 6, true)};
    DeterministicCryptoUtils.encryptField(plaintextField, noCurrentDerivedKeys).get();
  }

  public void generateEncryptedFieldHeaderValid() throws Exception {
    byte[] header = DeterministicCryptoUtils.generateEncryptedFieldHeader(4).get();
    byte[] expected = {0, 0, 0, 4, 0, 0};
    assertEqualBytes(header, expected);
  }

  public void generateEncryptedFieldHeaderMaxValue() throws Exception {
    byte[] header = DeterministicCryptoUtils.generateEncryptedFieldHeader(4294967295L).get();
    byte[] expected = {(byte) 255, (byte) 255, (byte) 255, (byte) 255, 0, 0};
    assertEqualBytes(header, expected);
  }


  @Test(expectedExceptions = java.util.concurrent.ExecutionException.class,
      expectedExceptionsMessageRegExp = ".*Failed to generate header.*")
  public void generateEncryptedFieldHeaderInvalidValue() throws Exception {
    DeterministicCryptoUtils.generateEncryptedFieldHeader(4294967295L + 1).get();
  }

  @Test(expectedExceptions = java.util.concurrent.ExecutionException.class,
      expectedExceptionsMessageRegExp = ".*Failed to generate header.*")
  public void generateEncryptedFieldHeaderInvalidValue2() throws Exception {
    DeterministicCryptoUtils.generateEncryptedFieldHeader(-1).get();
  }

  public void decomposeFieldValid() throws Exception {
    byte[] header = {0, 0, 0, 4, 0, 0, 1, 1};
    DeterministicEncryptedFieldParts parts = DeterministicCryptoUtils.decomposeField(header).get();
    long expectedTenantSecretId = 4;
    byte[] expectEdencryptedBytes = {1, 1};

    assertEquals(parts.getTenantSecretId(), expectedTenantSecretId);
    assertEqualBytes(parts.getEncryptedBytes(), expectEdencryptedBytes);
  }

  @Test(expectedExceptions = java.util.concurrent.ExecutionException.class,
      expectedExceptionsMessageRegExp = ".*Failed to parse.*")
  public void decomposeFieldFailsInvalidPadding() throws Exception {
    byte[] header = {0, 0, 0, 4, 0, 1, 1, 1};
    DeterministicCryptoUtils.decomposeField(header).get();
  }

  @Test(expectedExceptions = java.util.concurrent.ExecutionException.class,
      expectedExceptionsMessageRegExp = ".*Failed to parse.*")
  public void decomposeFieldFailsTooShort() throws Exception {
    byte[] header = {0, 0, 4, 0, 0};
    DeterministicCryptoUtils.decomposeField(header).get();
  }

  public void rotateFieldDecrypts() throws Exception {
    DeterministicEncryptedField encrypted =
        DeterministicCryptoUtils.encryptField(plaintextField, derivedKeys).get();

    DeterministicEncryptedField rotated =
        DeterministicCryptoUtils.rotateField(encrypted, newDerivedKeys).get();
    DeterministicPlaintextField decrypted =
        DeterministicCryptoUtils.decryptField(rotated, newDerivedKeys).get();
    assertEqualBytes(plaintextField.getPlaintextField(), decrypted.getPlaintextField());
  }

  public void checkRotationFieldNoOpWorksForChanged() throws Exception {
    DeterministicEncryptedField encrypted =
        DeterministicCryptoUtils.encryptField(plaintextField, derivedKeys).get();
    Boolean noOp = DeterministicCryptoUtils.checkRotationFieldNoOp(encrypted, newDerivedKeys).get();
    assertEquals(noOp, false);
  }

  public void checkRotationFieldNoOpWorksForNoOp() throws Exception {
    DeterministicEncryptedField encrypted =
        DeterministicCryptoUtils.encryptField(plaintextField, derivedKeys).get();
    Boolean noOp = DeterministicCryptoUtils.checkRotationFieldNoOp(encrypted, derivedKeys).get();
    assertEquals(noOp, true);
  }

  @Test(expectedExceptions = java.util.concurrent.ExecutionException.class,
      expectedExceptionsMessageRegExp = ".*Failed deterministic rotation.*")
  public void checkRotationFieldNoOpFailsForMissingCurrent() throws Exception {
    DeterministicEncryptedField encrypted =
        DeterministicCryptoUtils.encryptField(plaintextField, derivedKeys).get();
    DerivedKey[] newDerivedKeys = {new DerivedKey(
        "g2K8P7zoxO+yi4oDcR5Bk4grNuHFUBgqJ2Jgbh2bJzDk2Z/z8ji5WvF8aO2n/iUBl8tbKiaIs2n7R9vIBrXGmg==",
        5, false)};
    DeterministicCryptoUtils.checkRotationFieldNoOp(encrypted, newDerivedKeys).get();
  }

  @Test(expectedExceptions = java.util.concurrent.ExecutionException.class,
      expectedExceptionsMessageRegExp = ".*Failed deterministic rotation.*")
  public void checkRotationFieldNoOpFailsForMissingPreviousKey() throws Exception {
    DeterministicEncryptedField encrypted =
        DeterministicCryptoUtils.encryptField(plaintextField, derivedKeys).get();
    DerivedKey[] newDerivedKeys = {new DerivedKey(
        "g2K8P7zoxO+yi4oDcR5Bk4grNuHFUBgqJ2Jgbh2bJzDk2Z/z8ji5WvF8aO2n/iUBl8tbKiaIs2n7R9vIBrXGmg==",
        500, true)};
    DeterministicCryptoUtils.checkRotationFieldNoOp(encrypted, newDerivedKeys).get();
  }

  public void generateSearchTermsWorks() throws Exception {
    DeterministicEncryptedField[] encrypted =
        DeterministicCryptoUtils.generateSearchTerms(plaintextField, derivedKeys).get();
    assertEquals(encrypted.length, 2);
    DeterministicEncryptedFieldParts parts1 =
        DeterministicCryptoUtils.decomposeField(encrypted[0].getEncryptedField()).get();
    DeterministicEncryptedFieldParts parts2 =
        DeterministicCryptoUtils.decomposeField(encrypted[1].getEncryptedField()).get();
    assertEquals(parts1.getTenantSecretId() == parts2.getTenantSecretId(), false);
    DeterministicPlaintextField decrypted1 =
        DeterministicCryptoUtils.decryptField(encrypted[0], derivedKeys).get();
    DeterministicPlaintextField decrypted2 =
        DeterministicCryptoUtils.decryptField(encrypted[1], derivedKeys).get();
    assertEqualBytes(decrypted1.getPlaintextField(), plaintextField.getPlaintextField());
    assertEqualBytes(decrypted2.getPlaintextField(), plaintextField.getPlaintextField());
  }
}
