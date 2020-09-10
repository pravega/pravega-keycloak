/**
 * Copyright (c) 2019 Dell Inc., or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package io.pravega.keycloak.client;

import io.pravega.common.util.RetriesExhaustedException;
import io.pravega.keycloak.client.KeycloakAuthzClient.TokenCache;
import io.pravega.keycloak.client.helpers.AccessTokenBuilder;
import io.pravega.keycloak.client.helpers.AccessTokenIssuer;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.ClientAuthenticator;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.authorization.AuthorizationResponse;
import org.keycloak.util.BasicAuthHelper;
import org.mockito.Mockito;

import java.io.File;
import java.io.IOException;
import java.net.ConnectException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.BiFunction;

import static io.pravega.keycloak.client.KeycloakAuthzClient.DEFAULT_PRAVEGA_CONTROLLER_CLIENT_ID;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class KeycloakAuthzClientTest {
    private static final String SVC_ACCOUNT_JSON_FILE = getResourceFile("service-account.json");
    private static final String SVC_ACCOUNT_JSON_STRING = getResourceString(getResourceFile("service-account.json"));
    private static final AccessTokenIssuer ISSUER = new AccessTokenIssuer();

    @Test
    public void getRPTCacheHits() {
        AuthzClient client = mock(AuthzClient.class, Mockito.RETURNS_DEEP_STUBS);
        TokenCache tokenCache = spy(new TokenCache(0));

        // configure mocks
        AccessTokenResponse accessToken = accessTokenResponse();
        when(client.obtainAccessToken()).thenReturn(accessToken);
        AuthorizationResponse response = authResponse(false);
        when(client.authorization(any()).authorize(any())).thenReturn(response);

        // cache miss
        KeycloakAuthzClient authzClient = new KeycloakAuthzClient(client, tokenCache);
        String rpt1 = authzClient.getRPT();
        assertEquals(response.getToken(), rpt1);

        // cache hit
        String rpt2 = authzClient.getRPT();
        assertEquals(response.getToken(), rpt2);

        verify(tokenCache, times(2)).getIfValid();
        verify(client.authorization(any()), times(1)).authorize(any());
        verify(tokenCache, times(1)).update(any());
    }

    @Test
    public void getRPTFailsToGetAccessToken() {
        AuthzClient client = mock(AuthzClient.class, Mockito.RETURNS_DEEP_STUBS);
        TokenCache tokenCache = spy(new TokenCache(0));
        when(client.obtainAccessToken()).thenThrow(new HttpResponseException("", 400, "", null));

        KeycloakAuthzClient authzClient = new KeycloakAuthzClient(client, tokenCache);
        try {
            authzClient.getRPT();
            Assert.fail();
        } catch (KeycloakAuthenticationException e) {
        }
        verify(client, times(1)).obtainAccessToken();
    }

    @Test
    public void getRPTCannotExchangeAccessTokenForRPT() {
        AuthzClient client = mock(AuthzClient.class, Mockito.RETURNS_DEEP_STUBS);
        TokenCache tokenCache = spy(new TokenCache(0));
        AccessTokenResponse accessToken = accessTokenResponse();
        when(client.obtainAccessToken()).thenReturn(accessToken);
        when(client.authorization(any()).authorize(any())).thenThrow(new HttpResponseException("", 400, "", null));

        KeycloakAuthzClient authzClient = new KeycloakAuthzClient(client, tokenCache);
        try {
            authzClient.getRPT();
            Assert.fail();
        } catch (KeycloakAuthorizationException e) {
        }
        verify(client.authorization(any()), times(1)).authorize(any());
    }

    @Test
    public void getRPTWithHttp500Exception() {
        AuthzClient client = mock(AuthzClient.class, Mockito.RETURNS_DEEP_STUBS);
        TokenCache tokenCache = spy(new TokenCache(0));

        when(client.obtainAccessToken()).thenThrow(new HttpResponseException("", 500, "", null));
        KeycloakAuthzClient authzClient = new KeycloakAuthzClient(client, tokenCache, 3, 1);
        try {
            authzClient.getRPT();
            Assert.fail();
        } catch (RetriesExhaustedException e) {
        }
        verify(client, times(3)).obtainAccessToken();
    }

    @Test
    public void getRPTWithRuntimeConnectException() {
        AuthzClient client = mock(AuthzClient.class, Mockito.RETURNS_DEEP_STUBS);
        TokenCache tokenCache = spy(new TokenCache(0));

        when(client.obtainAccessToken()).thenThrow(new RuntimeException(new ConnectException()));
        KeycloakAuthzClient authzClient = new KeycloakAuthzClient(client, tokenCache, 3, 1);
        try {
            authzClient.getRPT();
            Assert.fail();
        } catch (RetriesExhaustedException e) {
        }
        verify(client, times(3)).obtainAccessToken();
    }

    @Test
    public void getRPTWithRandomRuntimeException() {
        AuthzClient client = mock(AuthzClient.class, Mockito.RETURNS_DEEP_STUBS);
        TokenCache tokenCache = spy(new TokenCache(0));

        when(client.obtainAccessToken()).thenThrow(new RuntimeException("bogus"));
        KeycloakAuthzClient authzClient = new KeycloakAuthzClient(client, tokenCache, 3, 1);
        try {
            authzClient.getRPT();
            Assert.fail();
        } catch (RetriesExhaustedException e) {
            Assert.fail();
        } catch (RuntimeException e) {
        }
        verify(client, times(1)).obtainAccessToken();
    }

    @Test
    public void tokenCacheExpiration() {
        AuthorizationResponse response;
        TokenCache tokenCache = new TokenCache(0);

        // cache miss
        response = tokenCache.getIfValid();
        assertNull(response);

        // cache hit
        response = authResponse(token(UUID.randomUUID().toString(), false));
        tokenCache.update(response);
        assertSame(response, tokenCache.getIfValid());

        // cache expiration
        response = authResponse(token(UUID.randomUUID().toString(), true));
        tokenCache.update(response);
        assertNull(tokenCache.getIfValid());
    }

    @Test
    public void builderDefaultAudience() {
        TestSupplier supplier = new TestSupplier();
        KeycloakAuthzClient.builder().withAuthzClientSupplier(supplier).withConfigFile(SVC_ACCOUNT_JSON_FILE).build();
        assertEquals(DEFAULT_PRAVEGA_CONTROLLER_CLIENT_ID, supplier.configuration.getResource());
    }

    @Test
    public void builderDefaultAudienceFromString() {
        TestSupplier supplier = new TestSupplier();
        KeycloakAuthzClient.builder().withAuthzClientSupplier(supplier).withConfigString(SVC_ACCOUNT_JSON_STRING).build();
        assertEquals(DEFAULT_PRAVEGA_CONTROLLER_CLIENT_ID, supplier.configuration.getResource());
    }

    @Test
    public void builderSetAudience() {
        TestSupplier supplier = new TestSupplier();
        KeycloakAuthzClient.builder().withAuthzClientSupplier(supplier).withConfigFile(SVC_ACCOUNT_JSON_FILE)
                .withAudience("builder_setAudience").build();
        assertEquals("builder_setAudience", supplier.configuration.getResource());
    }

    @Test
    public void builderSetAudienceFromString() {
        TestSupplier supplier = new TestSupplier();
        KeycloakAuthzClient.builder().withAuthzClientSupplier(supplier).withConfigString(SVC_ACCOUNT_JSON_STRING)
                .withAudience("builder_setAudience").build();
        assertEquals("builder_setAudience", supplier.configuration.getResource());
    }

    @Test(expected = KeycloakConfigurationException.class)
    public void builderNoConfig() {
        TestSupplier supplier = new TestSupplier();
        KeycloakAuthzClient.builder().withAuthzClientSupplier(supplier).build();
    }

    @Test
    void builderAuthenticator(boolean isFile) {
        TestSupplier supplier = new TestSupplier();
        if (isFile) {
            KeycloakAuthzClient.builder().withAuthzClientSupplier(supplier).withConfigFile(SVC_ACCOUNT_JSON_FILE).build();
        } else {
            KeycloakAuthzClient.builder().withAuthzClientSupplier(supplier).withConfigString(SVC_ACCOUNT_JSON_STRING).build();
        }
        Map<String, List<String>> requestParams = new HashMap<>();
        Map<String, String> requestHeaders = new HashMap<>();
        supplier.clientAuthenticator.configureClientCredentials(requestParams, requestHeaders);
        assertTrue(requestHeaders.containsKey("Authorization"));
        assertEquals(
                requestHeaders.get("Authorization"),
                BasicAuthHelper.createHeader("test-client", "b3f202cb-29fe-4d13-afb8-15e787c6e56c"));
    }

    @Test
    public void builder_authenticatorFromFile() {
        builderAuthenticator(true);
    }

    @Test
    public void builder_authenticatorFromString() {
        builderAuthenticator(false);
    }

    @Test
    public void checkDeserializeToken() {
        String goodToken = token(UUID.randomUUID().toString(), false);
        AccessToken token = KeycloakAuthzClient.toAccessToken(goodToken);
        assertFalse(token.isExpired());
        assertEquals(token.getSubject(), "00000000-0000-0000-0000-000000000001");
        assertEquals(token.getPreferredUsername(), "user-1");
    }

    private AccessTokenResponse accessTokenResponse() {
        AccessTokenResponse acr = new AccessTokenResponse();
        acr.setToken("TOKEN");
        return acr;
    }

    private AuthorizationResponse authResponse(String rawToken) {
        AuthorizationResponse response = new AuthorizationResponse();
        response.setToken(rawToken);
        return response;
    }

    private AuthorizationResponse authResponse(boolean expired) {
        String rawToken = token(UUID.randomUUID().toString(), expired);
        AuthorizationResponse response = new AuthorizationResponse();
        response.setToken(rawToken);
        return response;
    }

    private String token(String id, boolean expired) {
        AccessTokenIssuer issuer = new AccessTokenIssuer();

        AccessToken token = new AccessTokenBuilder()
                .id(id)
                .subject("00000000-0000-0000-0000-000000000001")
                .username("user-1").build();
        return issuer.issue(token, expired);
    }

    private static String getResourceFile(String resourceName) {
        return new File(KeycloakAuthzClientTest.class.getClassLoader().getResource(resourceName).getFile()).getAbsolutePath();
    }

    private static String getResourceString(String resourceFilePath) {
        try {
            return new String(Files.readAllBytes(Paths.get(resourceFilePath)));
        } catch (IOException e) {
            throw new RuntimeException("Could not load resource path: " + resourceFilePath, e);
        }
    }

    class TestSupplier implements BiFunction<Configuration, ClientAuthenticator, AuthzClient> {
        Configuration configuration;
        ClientAuthenticator clientAuthenticator;
        final AuthzClient client = mock(AuthzClient.class);

        @Override
        public AuthzClient apply(Configuration configuration, ClientAuthenticator clientAuthenticator) {
            this.configuration = configuration;
            this.clientAuthenticator = clientAuthenticator;
            return client;
        }
    }
}
