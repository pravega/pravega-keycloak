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

import org.junit.Test;
import org.keycloak.adapters.KeycloakDeployment;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static io.pravega.keycloak.client.KeycloakDeploymentResolver.DEFAULT_KEYCLOAK_SVC_CREDS_FILE;
import static io.pravega.keycloak.client.KeycloakDeploymentResolver.ENV_KEYCLOAK_SVC_CREDS_FILE;
import static org.junit.Assert.*;

public class KeycloakDeploymentResolverTest {

    private static final String NA_FILE = "non-existent.json";
    private static final String SVC_ACCOUNT_JSON_FILE = getResourceFile("service-account.json");
    private static final String CORRUPT_FILE = getResourceFile("corrupt.json");

    @Test
    public void getConfigFile_Explicit_NotSet() {
        Map<String, String> envs = Collections.emptyMap();
        Optional<Path> path = KeycloakDeploymentResolver.getConfigFile(envs, null, ENV_KEYCLOAK_SVC_CREDS_FILE, null);
        assertFalse(path.isPresent());
    }

    @Test
    public void getConfigFile_Explicit_NonExisting() {
        Map<String, String> envs = Collections.emptyMap();
        Optional<Path> path = KeycloakDeploymentResolver.getConfigFile(envs, NA_FILE, ENV_KEYCLOAK_SVC_CREDS_FILE, null);
        assertFalse(path.isPresent());
    }

    @Test
    public void getConfigFile_Explicit_Existing() {
        Map<String, String> envs = Collections.emptyMap();
        Optional<Path> path = KeycloakDeploymentResolver.getConfigFile(envs, SVC_ACCOUNT_JSON_FILE, ENV_KEYCLOAK_SVC_CREDS_FILE, null);
        assertTrue(path.isPresent());
        assertEquals(SVC_ACCOUNT_JSON_FILE, path.get().toString());
    }

    @Test
    public void getConfigFile_Env_NotSet() {
        Map<String, String> envs = Collections.emptyMap();
        Optional<Path> path = KeycloakDeploymentResolver.getConfigFile(envs, null, ENV_KEYCLOAK_SVC_CREDS_FILE, null);
        assertFalse(path.isPresent());
    }

    @Test
    public void getConfigFile_Env_NonExisting() {
        Map<String, String> envs = Collections.singletonMap(ENV_KEYCLOAK_SVC_CREDS_FILE, NA_FILE);
        Optional<Path> path = KeycloakDeploymentResolver.getConfigFile(envs, null, ENV_KEYCLOAK_SVC_CREDS_FILE, null);
        assertFalse(path.isPresent());
    }

    @Test
    public void getConfigFile_Env_Existing() {
        Map<String, String> envs = Collections.singletonMap(ENV_KEYCLOAK_SVC_CREDS_FILE, SVC_ACCOUNT_JSON_FILE);
        Optional<Path> path = KeycloakDeploymentResolver.getConfigFile(envs, null, ENV_KEYCLOAK_SVC_CREDS_FILE, null);
        assertTrue(path.isPresent());
        assertEquals(SVC_ACCOUNT_JSON_FILE, path.get().toString());
    }

    @Test
    public void getConfigFile_Default_NotSet() {
        Map<String, String> envs = Collections.emptyMap();
        Optional<Path> path = KeycloakDeploymentResolver.getConfigFile(envs, null, ENV_KEYCLOAK_SVC_CREDS_FILE, null);
        assertFalse(path.isPresent());
    }

    @Test
    public void getConfigFile_Default_NonExisting() {
        Map<String, String> envs = Collections.emptyMap();
        Optional<Path> path = KeycloakDeploymentResolver.getConfigFile(envs, null, ENV_KEYCLOAK_SVC_CREDS_FILE, NA_FILE);
        assertFalse(path.isPresent());
    }

    @Test
    public void getConfigFile_Default_Existing() {
        Map<String, String> envs = Collections.emptyMap();
        Optional<Path> path = KeycloakDeploymentResolver.getConfigFile(envs, null, ENV_KEYCLOAK_SVC_CREDS_FILE, SVC_ACCOUNT_JSON_FILE);
        assertTrue(path.isPresent());
        assertEquals(SVC_ACCOUNT_JSON_FILE, path.get().toString());
    }

    @Test
    public void resolve_NonExisting() {
        // assumptions about the test environment
        assertNull(System.getenv(ENV_KEYCLOAK_SVC_CREDS_FILE));
        assertFalse(Files.isReadable(Paths.get(DEFAULT_KEYCLOAK_SVC_CREDS_FILE)));

        Optional<KeycloakDeployment> deployment = KeycloakDeploymentResolver.resolve(null);
        assertFalse(deployment.isPresent());
    }

    @Test
    public void resolve_Existing() {
        // assumptions about the test environment
        assertNull(System.getenv(ENV_KEYCLOAK_SVC_CREDS_FILE));
        assertFalse(Files.isReadable(Paths.get(DEFAULT_KEYCLOAK_SVC_CREDS_FILE)));

        Optional<KeycloakDeployment> deployment = KeycloakDeploymentResolver.resolve(SVC_ACCOUNT_JSON_FILE);
        assertTrue(deployment.isPresent());
        checkDeployment(deployment.get());
    }

    @Test(expected = IllegalStateException.class)
    public void resolve_BadFormat() {
        // assumptions about the test environment
        assertNull(System.getenv(ENV_KEYCLOAK_SVC_CREDS_FILE));
        assertFalse(Files.isReadable(Paths.get(DEFAULT_KEYCLOAK_SVC_CREDS_FILE)));

        KeycloakDeploymentResolver.resolve(CORRUPT_FILE);
    }

    private static String getResourceFile(String resourceName) {
        return new File(KeycloakDeploymentResolverTest.class.getClassLoader().getResource(resourceName).getFile()).getAbsolutePath();
    }

    private static void checkDeployment(KeycloakDeployment deployment) {
        assertEquals("http://localhost:9090/auth", deployment.getAuthServerBaseUrl());
        assertEquals("master", deployment.getRealm());
        assertEquals("test-client", deployment.getResourceName());
        assertEquals("b3f202cb-29fe-4d13-afb8-15e787c6e56c", deployment.getResourceCredentials().get("secret"));
    }
}