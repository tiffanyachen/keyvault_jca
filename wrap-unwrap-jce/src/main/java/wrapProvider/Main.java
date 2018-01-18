package wrapProvider;

import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
		String kid = "https://tifchen-keyvault-fancy.vault.azure.net:443/keys/keykey";
		kvCipher.engineInit(Cipher.WRAP_MODE, key,  AlgorithmParameters.getInstance("OAEP"), new SecureRandom());
		
		SecretKey secretKey = new SecretKeySpec(new byte[10], "RSA");
		byte[] wrapped = kvCipher.engineWrap(secretKey);
//		Key newKey = kvCipher.engineUnwrap(wrapped, "RSA-OAEP", 0);
//		
//		System.out.println(wrapped);
//		System.out.println(newKey.getEncoded());

	}
	
}
