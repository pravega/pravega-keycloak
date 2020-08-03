/**
 * Copyright (c) 2019 Dell Inc., or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package io.pravega.keycloak.client;

import org.apache.http.HttpStatus;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.ClientAuthenticator;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.common.util.Time;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.util.BasicAuthHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Supplier;

/**
 * Wrapper to manage a service account obtaining access tokens and RPTs for a given audience
 */
public class KeycloakAuthzClient {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakAuthzClient.class);

    public static final String DEFAULT_PRAVEGA_CONTROLLER_CLIENT_ID = "pravega-controller";
    private static final int DEFAULT_TOKEN_MIN_TIME_TO_LIVE_SECS = 60;
    private static final int DEFAULT_HTTP_MAX_RETRIES = 10;
    private static final int DEFAULT_HTTP_RETRIES_DELAY_MSECS = 5000;

    private final AuthzClient client;
    private final TokenCache tokenCache;
    private int httpMaxRetries = DEFAULT_HTTP_MAX_RETRIES;
    private int httpRetriesDelayMsecs = DEFAULT_HTTP_RETRIES_DELAY_MSECS;

    /**
     * Builds a Keycloak authorization client.
     */
    public static Builder builder() {
        return new Builder();
    }

    public KeycloakAuthzClient(AuthzClient client, TokenCache tokenCache) {
        this.client = client;
        this.tokenCache = tokenCache;
    }

    /**
     * Get an RPT for the target audience.
     *
     * @return a encoded RPT.
     */
    public String getRPT() {
        AuthorizationResponse token;
        // check the token cache
        synchronized (tokenCache) {
            token = tokenCache.getIfValid();
        }

        if (token == null) {
            // obtain an access token with which to make an authorization request
            AccessTokenResponse accResponse;
            accResponse = withRetries( () -> client.obtainAccessToken());
            if (accResponse == null) {
                LOG.error("Failed to obtain access token from Keycloak");
                throw new KeycloakAuthenticationException();
            }
            LOG.info("Obtained access token from Keycloak");

            // obtain an RPT
            AuthorizationRequest request = new AuthorizationRequest();
            token = withRetries( () -> client.authorization(accResponse.getToken()).authorize(request));
            if (token == null) {
                LOG.error("Failed to obtain RPT from Keycloak");
                throw new KeycloakAuthorizationException();
            }
            LOG.info("Obtained RPT from Keycloak");

            // update the token cache
            synchronized (tokenCache) {
                tokenCache.update(token);
            }
        }

        return token.getToken();
    }

    public void setHttpMaxRetries(int retries) {
        httpMaxRetries = retries;
    }

    public void setHttpRetriesDelayMsecs(int delay) {
        httpRetriesDelayMsecs = delay;
    }

    /**
     * Executes a Keycloak client request with retries.
     * HttpResponseExceptions may occur.  If the error code contained within is BAD_REQUEST,
     * SC_UNAUTHORIZED or SC_FORBIDDEN, the request is not retried as this is an authentication error
     * and will not be retried.
     * Only HttpResponseExceptions with other error codes will be retried.
     * Other exceptions will not be caught and will not be retried.
     * @param f the client method to execute
     * @param <T>
     * @return
     */
    private <T> T withRetries(Supplier<T> f)  {
        RuntimeException lastE = new RuntimeException();
        for (int i = 0; i < httpMaxRetries; i++) {
            LOG.info("Try {} of {}", i+1, httpMaxRetries);
            try {
                return f.get();
            } catch (HttpResponseException e) {
                // BAD request here actually means authentication failed
                // ( "invalid client id/secret" ).  Do not retry those.
                lastE = e;
                LOG.error("Error while communicating with Keycloak: ", e);
                int statusCode = e.getStatusCode();
                if (statusCode == HttpStatus.SC_BAD_REQUEST ||
                        statusCode == HttpStatus.SC_UNAUTHORIZED ||
                        statusCode == HttpStatus.SC_FORBIDDEN ) {
                    LOG.error("Auth error {}.  This will not be retried.", statusCode);
                    return null;
                }
            }
            try {
                LOG.warn("Retrying...");
                Thread.sleep(httpRetriesDelayMsecs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        LOG.error(String.format("Could not obtain token after %d retries", DEFAULT_HTTP_MAX_RETRIES));
        throw lastE;
    }


    /**
     * Deserialize a raw access token into an AccessToken object.
     *
     * @param rawToken
     * @return
     */
    static AccessToken toAccessToken(String rawToken) {
        AccessToken accessToken;
        try {
            accessToken = new JWSInput(rawToken).readJsonContent(AccessToken.class);
        } catch (JWSInputException cause) {
            throw new IllegalArgumentException("Failed to deserialize token", cause);
        }
        return accessToken;
    }

    static class TokenCache {
        private final int tokenMinimumTimeToLiveSecs;

        public TokenCache(int tokenMinimumTimeToLiveSecs) {
            this.tokenMinimumTimeToLiveSecs = tokenMinimumTimeToLiveSecs;
        }

        AuthorizationResponse response;
        AccessToken token;

        public AuthorizationResponse getIfValid() {
            if (response != null && token != null && isTokenTimeToLiveSufficient()) {
                return response;
            }
            return null;
        }

        public void update(AuthorizationResponse response) {
            Objects.requireNonNull(response);
            this.token = toAccessToken(response.getToken());
            this.response = response;
        }

        boolean isTokenTimeToLiveSufficient() {
            return token.getExpiration() - tokenMinimumTimeToLiveSecs > Time.currentTime();
        }
    }

    public static class Builder {
        private String audience;
        private String configFile;
        private BiFunction<Configuration, ClientAuthenticator, AuthzClient> clientSupplier;

        public Builder() {
            audience = DEFAULT_PRAVEGA_CONTROLLER_CLIENT_ID;
            clientSupplier = AuthzClient::create;
        }

        /**
         * Sets the Keycloak client configuration file to use.
         * @param path a path to a Keycloak OIDC JSON file.
         */
        public Builder withConfigFile(String path) {
            this.configFile = path;
            return this;
        }

        /**
         * Sets the audience for the RPT ticket to obtain.
         *
         * The audience should be set to the Pravega controller's client identifier.  The default is 'pravega-controller'.
         * @param audience the audience client identifier to use.
         */
        public Builder withAudience(String audience) {
            this.audience = audience;
            return this;
        }

        /**
         * Sets the Keycloak {@link AuthzClient} authz client provider.  For test purposes only.
         * @param clientSupplier a function which maps to an authz client.
         */
        KeycloakAuthzClient.Builder withAuthzClientSupplier(BiFunction<Configuration, ClientAuthenticator, AuthzClient> clientSupplier) {
            this.clientSupplier = clientSupplier;
            return this;
        }

        public KeycloakAuthzClient build() {
            Configuration configuration;
            try {
                configuration = KeycloakConfigResolver.resolve(configFile).orElseThrow(() -> new KeycloakConfigurationException(
                        "Unable to resolve a Keycloak client configuration for Pravega authentication purposes.\n\n" +
                                "Use one of the following approaches to provide a client configuration (in Keycloak OIDC JSON format):\n" +
                                "1. Use a builder method to set the path to a file.\n" +
                                "2. Set the environment variable 'KEYCLOAK_SERVICE_ACCOUNT_FILE' to the path to a file.\n" +
                                "3. Update the classpath to contain a resource named 'keycloak.json'.\n" +
                                ""));
            } catch (IOException e) {
                throw new KeycloakConfigurationException("Unexpected error in resolving or loading the Keycloak client configuration", e);
            }

            // apply defaults
            if (configuration.getTokenMinimumTimeToLive() == 0) {
                configuration.setTokenMinimumTimeToLive(DEFAULT_TOKEN_MIN_TIME_TO_LIVE_SECS);
            }

            // create the Keycloak authz client
            ClientAuthenticator authenticator = createClientAuthenticator(configuration.getResource(), (String) configuration.getCredentials().get("secret"));
            AuthzClient client = clientSupplier.apply(configuration, authenticator);

            // hack: convey the intended audience by setting the configuration resource
            configuration.setResource(audience);

            return new KeycloakAuthzClient(client, new TokenCache(configuration.getTokenMinimumTimeToLive()));
        }

        /**
         * Creates a client authenticator which uses HTTP BASIC and client id and secret to authenticate the client.
         *
         * Note: this implementation captures the client id eagerly, unlike the default client authenticator used by {@link Configuration}.
         * This is important since the {@link Configuration} must have the target audience as its resource.
         *
         * @return the client authenticator
         */
        private ClientAuthenticator createClientAuthenticator(String clientId, String clientSecret) {
            return new ClientAuthenticator() {
                /**
                 * Configures a given Keycloak request to use client credentials for authentication purposes.
                 * This method is called iff a user access token isn't provided to the builder.
                 * see: ClientIdAndSecretCredentialsProvider
                 */
                @Override
                public void configureClientCredentials(Map<String, List<String>> requestParams, Map<String, String> requestHeaders) {
                    Objects.requireNonNull(clientId, "Client ID not provided.");
                    Objects.requireNonNull(clientSecret, "Client secret not provided.");
                    requestHeaders.put("Authorization", BasicAuthHelper.createHeader(clientId, clientSecret));
                }
            };
        }
    }
}
