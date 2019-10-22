/**
 * Copyright (c) 2019 Dell Inc., or its subsidiaries. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package io.pravega.keycloak.client.helpers;

import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.util.TokenUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;

/**
 * Builds {@link AccessToken Keycloak access tokens} for test purposes, with a subset of claims.
 * <p>
 * See the Keycloak server code for fields details:
 * - <a href="https://github.com/keycloak/keycloak/blob/4.0.0.Final/services/src/main/java/org/keycloak/protocol/oidc/TokenManager.java#L656">TokenManager.java</a>
 */
public class AccessTokenBuilder {

    private final AccessToken accessToken;

    public AccessTokenBuilder() {
        accessToken = new AccessToken();
        accessToken.setAuthorization(new AccessToken.Authorization());
        accessToken.type(TokenUtil.TOKEN_TYPE_BEARER);
    }

    public AccessTokenBuilder id(String id) {
        accessToken.id(id);
        return this;
    }

    public AccessTokenBuilder subject(String userId) {
        accessToken.subject(userId);
        return this;
    }

    public AccessTokenBuilder username(String userId) {
        accessToken.setOtherClaims("preferred_username", userId);
        return this;
    }

    public AccessTokenBuilder withResourceServerIdentity() {
        AccessToken.Access access = new AccessToken.Access();
        access.addRole("uma_protection");
        accessToken.setResourceAccess(Collections.singletonMap("pravega-controller", access));
        accessToken.setRealmAccess(access);
        return this;
    }

    public AccessTokenBuilder withAuthorizationForResource(String resourceName, String... scopes) {
        HashSet<String> scopesInPermission = new HashSet<>(Arrays.asList(scopes));
        Permission permission = new Permission();
        permission.setResourceName(resourceName);
        permission.setScopes(scopesInPermission);
        accessToken.getAuthorization().setPermissions(Collections.singletonList(permission));
        return this;
    }

    public AccessToken build() {
        return accessToken;
    }
}