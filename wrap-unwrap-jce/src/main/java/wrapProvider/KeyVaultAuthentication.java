package wrapProvider;

import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.rest.credentials.ServiceClientCredentials;

public class KeyVaultAuthentication {

	protected KeyVaultClient keyVaultClient;
	private Config config;

	public KeyVaultAuthentication(Config config) {
		this.config = config;
	}

	public KeyVaultClient getClient() {
		return this.keyVaultClient;
	}

	/**
	 * Primary vault URI, used for keys and secrets tests.
	 */
	public String getVaultUri() {
		return config.getVaultUri();
	}

	private static AuthenticationResult getAccessToken(String authorization, String resource, Config config)
			throws Exception {

		String clientId = config.getClientId();

		if (clientId == null) {
			throw new Exception("Please put clientId in the configuration file.");
		}

		String clientKey = config.getClientSecret();

		AuthenticationResult result = null;
		ExecutorService service = null;
		try {
			service = Executors.newFixedThreadPool(1);
			AuthenticationContext context = new AuthenticationContext(authorization, false, service);

			Future<AuthenticationResult> future = null;
			if (clientKey != null) {
				ClientCredential credentials = new ClientCredential(clientId, clientKey);
				future = context.acquireToken(resource, credentials, null);
			}

			if (future == null) {
				throw new Exception(
						"Missing or ambiguous credentials - please put clientSecret in the configuration file.");
			}

			result = future.get();
		} finally {
			service.shutdown();
		}

		if (result == null) {
			throw new RuntimeException("Authentication result was null.");
		}
		return result;
	}

	private static ServiceClientCredentials createKeyVaultCredentials(final Config config) throws Exception {
		return new KeyVaultCredentials() {

			@Override
			public String doAuthenticate(String authorization, String resource, String scope) {
				try {
					AuthenticationResult authResult = getAccessToken(authorization, resource, config);
					return authResult.getAccessToken();

				} catch (Exception ex) {
					throw new RuntimeException(ex);
				}
			}
		};
	}

	public void initializeClients() throws IOException {
		try {
			keyVaultClient = new KeyVaultClient(createKeyVaultCredentials(this.config));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
