package wrapProvider;

public class Main {
	
	public static void main (String [] args) throws Exception
	{
		//make input stream
		Config config = Config.getConfig("config.cfg", null);
		System.out.println(config.getClientId());
		System.out.println(config.getClientSecret());
		System.out.println(config.getVaultUri());
		

		KeyVaultCipher kvCipher = new KeyVaultCipher();
		String kid = "https://tifchen-keyvault-fancy.vault.azure.net:443/keys/keykey";
		kvCipher.engineInit(kid);
		byte[] result;
		byte[] plainText = new byte[100];
//        new Random(0x1234567L).nextBytes(plainText);
//        result = kvCipher.engineWrap(kid, JsonWebKeyEncryptionAlgorithm.RSA_OAEP.toString(), plainText);
//        System.out.println(result);

	}
	
}
