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

import io.pravega.keycloak.client.KeycloakAuthzClient.TokenCache;
import io.pravega.keycloak.client.helpers.AccessTokenBuilder;
import io.pravega.keycloak.client.helpers.AccessTokenIssuer;
import org.apache.http.HttpStatus;
import org.junit.Test;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.util.HttpResponseException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.mockito.Mockito;

import java.io.File;
import java.util.UUID;
import java.util.function.Supplier;

import static org.junit.Assert.*;

public class KeycloakAuthzClientTest {
    private static final String SVC_ACCOUNT_JSON_FILE = getResourceFile("service-account.json");
    private static final KeycloakDeployment DEPLOYMENT = KeycloakDeploymentResolver.resolve(SVC_ACCOUNT_JSON_FILE).get();

    @Test
    public void testKeyCloakAuthzClientCachedtoken() {

        AuthzClient client = Mockito.mock(AuthzClient.class, Mockito.RETURNS_DEEP_STUBS);
        // always generated an valid token Response.
        Supplier<AccessTokenResponse> generatedResponse = () -> {
            String rawToken = token(UUID.randomUUID().toString(), false);
            AccessTokenResponse response = new AccessTokenResponse();
            response.setToken(rawToken);
            response.setTokenType("bearer");
            return response;
        };
        Mockito.when(client.obtainAccessToken()).thenReturn(generatedResponse.get());
        Mockito.when(client.authorization().authorize().getToken()).thenReturn("RPT TOKEN");

        //null token
        TokenCache tokenCache = new TokenCache();
        KeycloakAuthzClient authzClient = new KeycloakAuthzClient(DEPLOYMENT)
                .withAuthzClientSupplier((s) -> client)
                .withTokenCache(tokenCache);
        authzClient.getRPT();
        Mockito.verify(client, Mockito.times(1)).obtainAccessToken();

        //generate a expired token.
        String expiredToken = token(UUID.randomUUID().toString(), true);
        tokenCache.setToken(expiredToken);
        authzClient.getRPT();
        Mockito.verify(client, Mockito.times(2)).obtainAccessToken();
        String token = tokenCache.getToken();
        assertNotEquals(expiredToken, token);

        //should not call obtainAccessToken()
        String goodToken = token(UUID.randomUUID().toString(), false);
        tokenCache.setToken(goodToken);
        authzClient.getRPT();
        Mockito.verify(client, Mockito.times(2)).obtainAccessToken();
        token = tokenCache.getToken();
        assertEquals(goodToken, token);
    }

    @Test(expected = KeycloakAuthenticationException.class)
    public void checkRethrowAuthenticationException() {
        HttpResponseException e = new HttpResponseException("Authentication Failed",
                HttpStatus.SC_BAD_REQUEST, null, null);
        AuthzClient client = Mockito.mock(AuthzClient.class, Mockito.RETURNS_DEEP_STUBS);
        Mockito.when(client.obtainAccessToken()).thenThrow(e);

        TokenCache tokenCache = new TokenCache();
        KeycloakAuthzClient authzClient = new KeycloakAuthzClient(DEPLOYMENT)
                .withAuthzClientSupplier((s) -> client)
                .withTokenCache(tokenCache);
        authzClient.getRPT();
    }

    @Test(expected = KeycloakAuthorizationException.class)
    public void checkRethrowAuthorizationException() {
        HttpResponseException inner = new HttpResponseException("Authorization Failed",
                HttpStatus.SC_BAD_REQUEST, null, null);
        RuntimeException e = new RuntimeException(inner);
        AuthzClient client = Mockito.mock(AuthzClient.class, Mockito.RETURNS_DEEP_STUBS);
        Mockito.when(client.obtainAccessToken().getToken()).thenReturn("access_token");
        Mockito.when(client.authorization("access_token")).thenThrow(e);

        TokenCache cachedToken = new TokenCache();
        KeycloakAuthzClient authzClient = new KeycloakAuthzClient(DEPLOYMENT)
                .withAuthzClientSupplier((s) -> client)
                .withTokenCache(cachedToken);

        authzClient.getRPT();
    }

    @Test
    public void checkDeserializeToken() {
        String goodToken = token(UUID.randomUUID().toString(), false);
        AccessToken token = KeycloakAuthzClient.toAccessToken(goodToken);
        assertFalse(token.isExpired());
        assertEquals(token.getSubject(), "00000000-0000-0000-0000-000000000001");
        assertEquals(token.getPreferredUsername(), "user-1");
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
        return new File(KeycloakDeploymentResolverTest.class.getClassLoader().getResource(resourceName).getFile()).getAbsolutePath();
    }
}
