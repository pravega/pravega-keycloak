package io.pravega.keycloak.client;

import org.apache.http.HttpStatus;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.authentication.ClientCredentialsProviderUtils;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Wrapper to manage a service account obtaining access tokens and RPTs for a given audience
 */
public class KeycloakAuthzClient {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthzClient.class);

    public static final String PRAVEGA_CONTROLLER_AUDIENCE = "pravega-controller";

    private final KeycloakDeployment deployment;
    private String audience;
    private Function<String, AuthzClient> authzClientSupplier;
    private TokenCache tokenCache;

    /**
     * Factory to automatically create a client without explicit parameters.
     * This will use the KeycloakDeploymentResolver to discover where the keycloak.json file resides
     */
    public static KeycloakAuthzClient client() {
        KeycloakDeployment deployment = KeycloakDeploymentResolver.resolve()
                .orElseThrow(() -> new IllegalStateException("Unable to resolve a Keycloak adapter configuration."));
        return new KeycloakAuthzClient(deployment);
    }

    /**
     * Create a client directly from a deployment
     */
    public KeycloakAuthzClient(KeycloakDeployment deployment) {
        this.deployment = deployment;
        this.audience = PRAVEGA_CONTROLLER_AUDIENCE;
        this.tokenCache = new TokenCache();
        this.authzClientSupplier = this::getInternalAuthzClient;
    }

    public KeycloakAuthzClient withAudience(String audience) {
        this.audience = audience;
        return this;
    }

    public KeycloakAuthzClient withTokenCache(TokenCache tokenCache) {
        this.tokenCache = tokenCache;
        return this;
    }

    public KeycloakAuthzClient withAuthzClientSupplier(Function<String, AuthzClient> clientSupplier) {
        this.authzClientSupplier = clientSupplier;
        return this;
    }

    /**
     * Get an RPT for the target audience.
     *
     * @return a encoded RPT.
     */
    public String getRPT() {
        try {
            // use the cached authz Client to obtain the initial access token
            // for the service account itself
            if (tokenCache.getToken() == null || toAccessToken(tokenCache.getToken()).isExpired()) {
                String token = authzClientSupplier.apply(null).obtainAccessToken().getToken();
                tokenCache.setToken(token);
                LOG.info("Access token acquired, now acquiring RPT for Pravega");
            }
        } catch (HttpResponseException e) {
            LOG.error("Unable to acquire access token {}", e.getMessage());
            specializeOrRethrow(e);
        }

        try {
            // get a new authz client, targeted at the specified audience and use the
            // previously acquired access token as authentication
            return authzClientSupplier.apply(audience)
                    .authorization(tokenCache.getToken())
                    .authorize(new AuthorizationRequest())
                    .getToken();
        } catch (RuntimeException e) {
            LOG.error("Unable to acquire RPT {}", e.getMessage());
            specializeOrRethrow(e);
        }
        return null;
    }

    /**
     * Deserialize a raw access token into an AccessToken object.
     *
     * @param rawToken
     * @return
     */
    public static AccessToken toAccessToken(String rawToken) {
        AccessToken accessToken;
        try {
            accessToken = new JWSInput(rawToken).readJsonContent(AccessToken.class);
        } catch (JWSInputException cause) {
            throw new RuntimeException("Failed to deserialize token", cause);
        }
        return accessToken;
    }

    /**
     * Constructs an AuthzClient with an optionally passed target audience.
     * The pravega-controller is the assumed audience if none is explicitly passed.
     *
     * @param targetAudience
     * @return
     */
    private AuthzClient getInternalAuthzClient(String targetAudience) {
        String audienceToUse = targetAudience == null ? deployment.getResourceName() : targetAudience;

        Configuration config = new Configuration(
                deployment.getAuthServerBaseUrl(),
                deployment.getRealm(),
                audienceToUse,
                deployment.getResourceCredentials(),
                deployment.getClient());

        return AuthzClient.create(config, (Map<String, List<String>> requestParams, Map<String, String> requestHeaders) -> {
                    // configure the client with service account credentials
                    Map<String, String> formparams = new HashMap<>();
                    ClientCredentialsProviderUtils.setClientCredentials(deployment, requestHeaders, formparams);
                    for (Map.Entry<String, String> param : formparams.entrySet()) {
                        requestParams.put(param.getKey(), Arrays.asList(param.getValue()));
                    }
                }
        );
    }

    private AuthzClient getInternalAuthzClient() {
        return getInternalAuthzClient(null);
    }

    /**
     * If the exception is HttpResponse and had a code of BAD_REQUEST, rethrow
     * as KeycloakAuthenticationException, else rethrow as is
     *
     * @param e
     */
    private static void specializeOrRethrow(HttpResponseException e) {
        if (e.getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
            throw new KeycloakAuthenticationException(e);
        }
        throw e;
    }

    /**
     * If the exception is RuntimeException and has a non null cause of HttpResponseException with
     * code of BAD_REQUEST, rethrow as KeycloakAuthorizationException, else rethrow as is
     *
     * @param e
     */
    private static void specializeOrRethrow(RuntimeException e) {
        Throwable t = e.getCause();
        if (t != null && t.getClass().isAssignableFrom(HttpResponseException.class) &&
                ((HttpResponseException) t).getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
            throw new KeycloakAuthorizationException(e);
        }
        throw e;
    }

    public static class TokenCache {

        private volatile String cachedToken;

        public String getToken() {
            return cachedToken;
        }

        public void setToken(String t) {
            cachedToken = t;
        }
    }
}
