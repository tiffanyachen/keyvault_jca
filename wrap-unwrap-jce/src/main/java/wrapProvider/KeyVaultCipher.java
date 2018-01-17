package wrapProvider;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.ExecutionException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.extensions.KeyVaultKey;
import com.microsoft.azure.keyvault.extensions.KeyVaultKeyResolver;

public class KeyVaultCipher extends CipherSpi {
	
	KeyVaultAuthentication keyVaultAuthentication;
	KeyVaultKey encryptionKey;
	KeyVaultKeyResolver keyVaultKeyResolver;
	String encryptionKeyId;
	KeyVaultClient keyVaultClient;
	String algorithm;
	
	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		throw new UnsupportedOperationException("This operation is not supported.");
	}

	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {
		throw new UnsupportedOperationException("This operation is not supported.");
	}

	@Override
	protected int engineGetBlockSize() {
		throw new UnsupportedOperationException("This operation is not supported.");
	}

	@Override
	protected int engineGetOutputSize(int inputLen) {
		throw new UnsupportedOperationException("This operation is not supported.");
	}

	@Override
	protected byte[] engineGetIV() {
		throw new UnsupportedOperationException("This operation is not supported.");
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		throw new UnsupportedOperationException("This operation is not supported.");
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
		throw new UnsupportedOperationException("Please provide an algorithm parameter.");
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		try {
			engineInit(opmode, key, AlgorithmParameters.getInstance(params.toString()), random);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw new InvalidAlgorithmParameterException("Invalid algorithm");
		}
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		KeyVaultKeyIdKey keyVaultKeyIdKey;
		if  (!(key instanceof KeyVaultKeyIdKey)) {
			throw new InvalidKeyException("This engine only takes in a KeyVaultKeyIdKey.");
		} else {
			keyVaultKeyIdKey = (KeyVaultKeyIdKey) key;
		}
		
		if ((opmode == Cipher.ENCRYPT_MODE) || (opmode == Cipher.DECRYPT_MODE)) {
			throw new UnsupportedOperationException("This mode not implemented");
		}
		
		this.encryptionKey = keyVaultKeyIdKey.getEncryptionKey();
		this.algorithm = params.getAlgorithm();
	}
	
	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		throw new UnsupportedOperationException("This operation is not supported.");
	}

	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException {
		throw new UnsupportedOperationException("This operation is not supported.");
	}

	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {
		throw new UnsupportedOperationException("This operation is not supported.");
	}

	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		throw new UnsupportedOperationException("This operation is not supported.");
	}
	
	@Override
	 protected byte[] engineWrap(Key key)
		        throws IllegalBlockSizeException, InvalidKeyException{
		
		if (!(key instanceof SecretKey)) {
			throw new UnsupportedOperationException("This key is not supported for this operation");
		}
		
		SecretKey secretKey = (SecretKey) key;
		try {
			return encryptionKey.wrapKeyAsync(secretKey.getEncoded(), algorithm).get().getKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		} catch (ExecutionException e) {
			e.printStackTrace();
		}
		return new byte[0];
	 }
	 
	
	@Override
	protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType) {
		Key key = null;
		try {
			key = new SecretKeySpec(encryptionKey.unwrapKeyAsync(wrappedKey, wrappedKeyAlgorithm).get(), this.algorithm);
		} catch (InterruptedException e) {
			e.printStackTrace();
		} catch (ExecutionException e) {
			e.printStackTrace();
		}
		return key;
	}

}
