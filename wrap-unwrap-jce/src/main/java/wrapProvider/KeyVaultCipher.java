package wrapProvider;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Random;
import java.util.concurrent.ExecutionException;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.extensions.KeyVaultKey;
import com.microsoft.azure.keyvault.extensions.KeyVaultKeyResolver;

public class KeyVaultCipher extends CipherSpi {
	
	KeyVaultAuthentication keyVaultAuthentication;
	KeyVaultKey encryptionKey;
	KeyVaultKeyResolver keyVaultKeyResolver;
	String encryptionKeyId;
	KeyVaultClient keyVaultClient;
	

	
	private void init(String kid) throws IOException, InterruptedException, ExecutionException {
		Config config = Config.getConfig("config.cfg", null);
		keyVaultAuthentication = new KeyVaultAuthentication(config);
		keyVaultAuthentication.initializeClients();
		keyVaultClient = keyVaultAuthentication.getClient();
		
		
		
		keyVaultKeyResolver = new KeyVaultKeyResolver(keyVaultAuthentication.getClient());
		this.encryptionKey = (KeyVaultKey) keyVaultKeyResolver.resolveKeyAsync(kid).get();
		this.encryptionKeyId = encryptionKey.getKid();
		System.out.println(encryptionKey.getDefaultEncryptionAlgorithm());
		byte[] plainText = new byte[100];
        new Random(0x1234567L).nextBytes(plainText);
		try {
			System.out.println(encryptionKey.wrapKeyAsync(plainText, "RSA_OAEP").get().getLeft());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(encryptionKey.getKid());
	}

	@Override
	protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected void engineSetPadding(String padding) throws NoSuchPaddingException {
		// TODO Auto-generated method stub
		
	}

	@Override
	protected int engineGetBlockSize() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	protected int engineGetOutputSize(int inputLen) {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	protected byte[] engineGetIV() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected AlgorithmParameters engineGetParameters() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
		// TODO Auto-generated method stub-
		
//		try {
//			//init("");
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
//		try {
//			//init
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
		
		
	}

	@Override
	protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
			throws InvalidKeyException, InvalidAlgorithmParameterException {
		// TODO Auto-generated method stub
//		try {
//			init();
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
	}
	
	protected void engineInit(String kid) throws IOException, InterruptedException, ExecutionException {
		init(kid);
		System.out.println("in engine init");
	}

	@Override
	protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
			throws IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
			throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
		return 0;
	}
	
	
	protected byte[] engineUnwrap(byte[] wrappedKey, String alg) throws InterruptedException, ExecutionException {
		return encryptionKey.unwrapKeyAsync(wrappedKey, alg).get();
	}
	
	protected byte[] engineWrap(String alg, byte[] plainText) throws NoSuchAlgorithmException, InterruptedException, ExecutionException {
		
		return encryptionKey.wrapKeyAsync(plainText, alg).get().getKey();
		
		
	}
	

}
