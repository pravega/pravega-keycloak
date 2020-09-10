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

import com.google.common.base.Strings;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.util.JsonSerialization;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Optional;

/**
 * A resolver for Keycloak {@link Configuration} objects.
 *
 * The following methods are attempted, in order, to load a Keycloak adapter configuration:
 * 1. an explicit file location pointing to a Keycloak adapter configuration file
 * 2. an environment variable pointing to the location of an adapter configuration file
 * 3. a classpath resource named keycloak.json
 */
public class KeycloakConfigResolver {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakConfigResolver.class);

    public static final String ENV_KEYCLOAK_SVC_CREDS_FILE = "KEYCLOAK_SERVICE_ACCOUNT_FILE";
    public static final String RESOURCE_KEYCLOAK_JSON = "keycloak.json";

    /**
     * Resolves a {@link Configuration} using the available methods.
     * @return a {@link Configuration} if found.
     */
    public static Optional<Configuration> resolve() throws IOException {
        return resolve(null);
    }

    /**
     * Resolves a {@link Configuration} using the available methods.
     * @param fileLocation location of an adapter configuration file
     * @return a {@link Configuration} if found.
     */
    public static Optional<Configuration> resolve(String fileLocation) throws IOException {
        return resolve(null, fileLocation);
    }

    /**
     * Resolves a {@link Configuration} using the available methods.
     *
     * @param configString adapter configuration  file content as a String
     * @return a {@link Configuration} if found.
     */
    public static Optional<Configuration> resolveFromString(String configString) throws IOException {
        return resolve(configString, null);
    }

    /**
     * Resolves a {@link Configuration} using the available methods.
     *
     * @param configString adapter configuration  file content as a String
     * @param fileLocation location of an adapter configuration file
     * @return a {@link Configuration} if found.
     */
    static Optional<Configuration> resolve(String configString, String fileLocation) throws IOException {

        Optional<InputStream> stream = open(configString, fileLocation, System.getenv(), Thread.currentThread().getContextClassLoader());
        if (!stream.isPresent()) {
            LOG.debug("Keycloak adapter configuration not found");
            return Optional.empty();
        }

        try (InputStream configStream = stream.get()) {
            try {
                return Optional.of(JsonSerialization.readValue(configStream, Configuration.class));
            } catch (Exception e) {
                throw new IOException("Could not parse configuration.", e);
            }
        }
    }

    static Optional<InputStream> open(String configString, String fileLocation, Map<String, String> envs, ClassLoader classLoader) throws IOException {
        Optional<InputStream> stream;
        stream = string(configString);
        if (stream.isPresent()) return stream;
        stream = path(fileLocation);
        if (stream.isPresent()) return stream;
        stream = env(envs);
        if (stream.isPresent()) return stream;
        stream = classpath(classLoader);
        return stream;
    }

    static Optional<InputStream> string(String configString) {
        if (!Strings.isNullOrEmpty(configString)) {
            LOG.debug("Loaded configuration from string");
            return Optional.of(new ByteArrayInputStream(configString.getBytes(StandardCharsets.UTF_8)));
        }
        return Optional.empty();
    }

    static Optional<InputStream> path(String fileLocation) throws IOException {
        Optional<Path> path = pathIfExists(fileLocation);
        if (path.isPresent()) {
            LOG.debug("Loaded configuration from file: {}", path);
            return Optional.of(Files.newInputStream(path.get()));
        }
        return Optional.empty();
    }

    static Optional<InputStream> env(Map<String, String> envs) throws IOException {
        return path(envs.get(ENV_KEYCLOAK_SVC_CREDS_FILE));
    }

    static Optional<InputStream> classpath(ClassLoader classLoader) throws IOException {
        Optional<InputStream> stream = Optional.ofNullable(classLoader.getResourceAsStream(RESOURCE_KEYCLOAK_JSON));
        if (stream.isPresent()) {
            LOG.debug("Loaded configuration from classpath");
        }
        return stream;
    }

    static Optional<Path> pathIfExists(String pathStr) {
        return Optional.ofNullable(pathStr).map(Paths::get).filter(Files::isReadable);
    }
}
