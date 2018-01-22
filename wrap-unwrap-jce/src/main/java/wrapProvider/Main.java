package wrapProvider;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;

public class Main {
	
	public static void main (String [] args) throws Exception
	{
		//make input stream
		Config config = Config.getConfig("config.cfg", null);
		System.out.println(config.getClientId());
		System.out.println(config.getClientSecret());
		System.out.println(config.getVaultUri());
		
		
		KeyVaultKeyIdKey key = new KeyVaultKeyIdKey("https://tifchen-keyvault-fancy.vault.azure.net:443/keys/keykey");
		KeyVaultCipher kvCipher = new KeyVaultCipher();
		kvCipher.engineInit(Cipher.WRAP_MODE, key,  AlgorithmParameters.getInstance("OAEP"), new SecureRandom());
        byte[] plainText = new byte[100];
        new Random(0x1234567L).nextBytes(plainText);
		SecretKey secretKey = new SecretKeySpec(plainText, "RSA");
		System.out.println(secretKey.getEncoded());
		byte[] wrapped = kvCipher.engineWrap(secretKey);
		Key newKey = kvCipher.engineUnwrap(wrapped, "RSA-OAEP", 0);
		System.out.println(newKey.getEncoded());
		Assert.assertArrayEquals(secretKey.getEncoded(), newKey.getEncoded());
		Assert.assertEquals(1, 2);
	}
	
}
