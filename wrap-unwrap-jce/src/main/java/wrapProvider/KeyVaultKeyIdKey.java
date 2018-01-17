package wrapProvider;

import java.security.Key;
import java.util.concurrent.ExecutionException;

import com.microsoft.azure.keyvault.extensions.KeyVaultKey;
import com.microsoft.azure.keyvault.extensions.KeyVaultKeyResolver;
import com.microsoft.azure.keyvault.webkey.JsonWebKey;

public class KeyVaultKeyIdKey implements Key{
	
	private static final long serialVersionUID = 1L;
	private final KeyVaultAuthentication keyVaultAuthentication;
	private final KeyVaultKey encryptionKey;
	private final KeyVaultKeyResolver keyVaultKeyResolver;
	private final JsonWebKey key;
	private final String encryptionKeyId;
	
	/**
	 * Takes in a Key Vault keyId for this Key. This should be versioned.
	 * 
	 * @param keyId
	 * @throws Exception 
	 */
	public KeyVaultKeyIdKey(String keyId) throws ConfigurationException {

		Config config;		
		try {
			config = Config.getConfig("config.cfg", null);
		} catch (Exception e) {
			throw new ConfigurationException("Missing a configuration file.");
		}
		
		keyVaultAuthentication = new KeyVaultAuthentication(config);
		try {
			keyVaultAuthentication.initializeClients();
		} catch (Exception e) {
			e.printStackTrace();
			throw new ConfigurationException("Error with getting the access token - check your credentials.");
		}	
		
		keyVaultKeyResolver = new KeyVaultKeyResolver(keyVaultAuthentication.getClient());
		key = keyVaultAuthentication.getClient().getKey(keyId).key();
		
		try {
			this.encryptionKey = (KeyVaultKey) keyVaultKeyResolver.resolveKeyAsync(keyId).get();
		} catch (InterruptedException e) {
			e.printStackTrace();
			throw new ConfigurationException("Communication with the service was interrupted - check your credentials.");
		} catch (ExecutionException e) {
			e.printStackTrace();
			throw new ConfigurationException("Trouble executing the authentication request - check your credentials.");
		}
		this.encryptionKeyId = encryptionKey.getKid();

	}
	
	public KeyVaultKey getEncryptionKey() {
		return this.encryptionKey;
	}

	public String getAlgorithm() {
		return key.kty().toString();
	}

	public String getFormat() {
		return key.toRSA().getPublic().getFormat();
	}

	public byte[] getEncoded() {
		return key.toRSA().getPublic().getEncoded();
	}
	
	public String getKeyId() {
		return this.encryptionKeyId;
	}

	public JsonWebKey getKey() {
		return this.key;
	}
}
