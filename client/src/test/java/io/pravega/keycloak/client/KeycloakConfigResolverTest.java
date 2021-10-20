/**
 * Copyright Pravega Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.pravega.keycloak.client;

import org.junit.Test;
import org.keycloak.authorization.client.Configuration;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import static io.pravega.keycloak.client.KeycloakConfigResolver.ENV_KEYCLOAK_SVC_CREDS_FILE;
import static io.pravega.keycloak.client.KeycloakConfigResolver.RESOURCE_KEYCLOAK_JSON;
import static org.junit.Assert.*;

public class KeycloakConfigResolverTest {

    private static final String NA_FILE = "non-existent.json";
    private static final String SVC_ACCOUNT_JSON_FILE = getResourceFile("service-account.json");
    private static final String CORRUPT_FILE = getResourceFile("corrupt.json");

    @Test
    public void open_Path_NotSet() throws IOException {
        Optional<InputStream> stream = KeycloakConfigResolver.path(null);
        assertFalse(stream.isPresent());
    }

    @Test
    public void open_Path_NonExisting() throws IOException {
        Optional<InputStream> stream = KeycloakConfigResolver.path(NA_FILE);
        assertFalse(stream.isPresent());
    }

    @Test
    public void open_Path_Existing() throws IOException {
        Optional<InputStream> stream = KeycloakConfigResolver.path(SVC_ACCOUNT_JSON_FILE);
        assertTrue(stream.isPresent());
        stream.get().close();
    }

    @Test
    public void open_Env_NotSet() throws IOException {
        Map<String, String> envs = Collections.emptyMap();
        Optional<InputStream> stream = KeycloakConfigResolver.env(envs);
        assertFalse(stream.isPresent());
    }

    @Test
    public void open_Env_NonExisting() throws IOException {
        Map<String, String> envs = Collections.singletonMap(ENV_KEYCLOAK_SVC_CREDS_FILE, NA_FILE);
        Optional<InputStream> stream = KeycloakConfigResolver.env(envs);
        assertFalse(stream.isPresent());
    }

    @Test
    public void open_Env_Existing() throws IOException {
        Map<String, String> envs = Collections.singletonMap(ENV_KEYCLOAK_SVC_CREDS_FILE, SVC_ACCOUNT_JSON_FILE);
        Optional<InputStream> stream = KeycloakConfigResolver.env(envs);
        assertTrue(stream.isPresent());
        stream.get().close();
    }

    @Test
    public void open_Classpath_NonExisting() throws IOException {
        ClassLoader cl = new TestClassLoader(null);
        Optional<InputStream> stream = KeycloakConfigResolver.classpath(cl);
        assertFalse(stream.isPresent());
    }

    @Test
    public void open_Classpath_Existing() throws IOException {
        ClassLoader cl = new TestClassLoader(SVC_ACCOUNT_JSON_FILE);
        Optional<InputStream> stream = KeycloakConfigResolver.classpath(cl);
        assertTrue(stream.isPresent());
        stream.get().close();
    }

    @Test
    public void resolve_NonExisting() throws Exception {
        // assumptions about the test environment
        assertNull(System.getenv(ENV_KEYCLOAK_SVC_CREDS_FILE));
        assertNull(Thread.currentThread().getContextClassLoader().getResource(RESOURCE_KEYCLOAK_JSON));

        Optional<Configuration> configuration = KeycloakConfigResolver.resolve(null);
        assertFalse(configuration.isPresent());
    }

    @Test
    public void resolve_Existing() throws Exception {
        // assumptions about the test environment
        assertNull(System.getenv(ENV_KEYCLOAK_SVC_CREDS_FILE));
        assertNull(Thread.currentThread().getContextClassLoader().getResource(RESOURCE_KEYCLOAK_JSON));

        Optional<Configuration> configuration = KeycloakConfigResolver.resolve(SVC_ACCOUNT_JSON_FILE);
        assertTrue(configuration.isPresent());
        checkConfiguration(configuration.get());
    }

    @Test(expected = IOException.class)
    public void resolve_BadFormat() throws Exception {
        // assumptions about the test environment
        assertNull(System.getenv(ENV_KEYCLOAK_SVC_CREDS_FILE));
        assertNull(Thread.currentThread().getContextClassLoader().getResource(RESOURCE_KEYCLOAK_JSON));

        KeycloakConfigResolver.resolve(CORRUPT_FILE);
    }

    private static String getResourceFile(String resourceName) {
        return new File(KeycloakConfigResolverTest.class.getClassLoader().getResource(resourceName).getFile()).getAbsolutePath();
    }

    private static void checkConfiguration(Configuration configuration) {
        assertEquals("http://localhost:9090/auth", configuration.getAuthServerUrl());
        assertEquals("master", configuration.getRealm());
        assertEquals("test-client", configuration.getResource());
        assertEquals("b3f202cb-29fe-4d13-afb8-15e787c6e56c", configuration.getCredentials().get("secret"));
    }

    static class TestClassLoader extends ClassLoader {
        private final String configPath;

        public TestClassLoader(String configPath) {
            this.configPath = configPath;
        }

        @Override
        public InputStream getResourceAsStream(String name) {
            if (RESOURCE_KEYCLOAK_JSON.equals(name) && configPath != null) {
                try {
                    return new FileInputStream(configPath);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
            return null;
        }
    }
}