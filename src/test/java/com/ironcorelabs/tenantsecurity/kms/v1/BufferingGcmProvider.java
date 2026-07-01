package com.ironcorelabs.tenantsecurity.kms.v1;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

// Test-only JCE provider used to reproduce the BC-FIPS AEAD buffering behavior
// that surfaces in issue #167. Every engineUpdate call buffers input and returns
// null; buffered bytes are released only at engineDoFinal. See
// CryptoUtilsTest#streamingRoundtripWithBufferingProvider.
public class BufferingGcmProvider extends Provider {
  public BufferingGcmProvider() {
    super("BufferingGcmTest", "1.0", "Test provider buffering GCM data like BC-FIPS");
    put("Cipher.AES/GCM/NoPadding", BufferingGcmCipherSpi.class.getName());
  }

  public static class BufferingGcmCipherSpi extends CipherSpi {
    private final Cipher delegate;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public BufferingGcmCipherSpi() throws Exception {
      delegate = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    }

    @Override
    protected void engineSetMode(String mode) {}

    @Override
    protected void engineSetPadding(String padding) {}

    @Override
    protected int engineGetBlockSize() {
      return delegate.getBlockSize();
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
      return delegate.getOutputSize(inputLen + buffer.size());
    }

    @Override
    protected byte[] engineGetIV() {
      return delegate.getIV();
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
      return delegate.getParameters();
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
      buffer.reset();
      delegate.init(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
        SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
      buffer.reset();
      delegate.init(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
        throws InvalidKeyException, InvalidAlgorithmParameterException {
      buffer.reset();
      delegate.init(opmode, key, params, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
      if (input != null && inputLen > 0) {
        buffer.write(input, inputOffset, inputLen);
      }
      return null;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
        int outputOffset) {
      if (input != null && inputLen > 0) {
        buffer.write(input, inputOffset, inputLen);
      }
      return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
        throws IllegalBlockSizeException, BadPaddingException {
      if (input != null && inputLen > 0) {
        buffer.write(input, inputOffset, inputLen);
      }
      byte[] all = buffer.toByteArray();
      buffer.reset();
      return delegate.doFinal(all);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
        int outputOffset)
        throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
      byte[] result = engineDoFinal(input, inputOffset, inputLen);
      if (output.length - outputOffset < result.length) {
        throw new ShortBufferException();
      }
      System.arraycopy(result, 0, output, outputOffset, result.length);
      return result.length;
    }
  }
}
