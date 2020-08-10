/**
 * Copyright (c) 2019 Dell Inc., or its subsidiaries. All Rights Reserved.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package io.pravega.keycloak.client;

import io.pravega.client.stream.impl.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static io.pravega.auth.AuthConstants.BEARER;

/**
 * Keycloak implementation of the Pravega Credentials interface, based on
 * Keycloak JWT tokens.
 */
public class PravegaKeycloakCredentials implements Credentials {
    private static final long serialVersionUID = 1L;
    private static final Logger LOG = LoggerFactory.getLogger(PravegaKeycloakCredentials.class);

    // The actual keycloak client won't be serialized.
    private transient KeycloakAuthzClient kc = null;
    private String keycloakJsonString = null;

    public PravegaKeycloakCredentials() {
        init();
        LOG.info("Loaded Keycloak Credentials");
    }

    public PravegaKeycloakCredentials(String keycloakJsonString) {
        this.keycloakJsonString = keycloakJsonString;
        init();
        LOG.info("Loaded Keycloak Credentials");
    }

    @Override
    public String getAuthenticationType() {
        return BEARER;
    }

    @Override
    public String getAuthenticationToken() {
        init();
        return kc.getRPT();
    }

    private void init() {
        if (kc == null) {
            if (keycloakJsonString != null) {
                try {
                    // KeycloakAuthzClient requires a file. We write the authentication credentials to
                    // a secure file and delete it immediately after initialization.
                    final Path tempPath = Files.createTempFile("keycloak-", ".json",
                            // Only user has permissions to the file.
                            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                    try {
                        try (PrintWriter out = new PrintWriter(tempPath.toFile())) {
                            out.println(keycloakJsonString);
                        }
                        kc = KeycloakAuthzClient.builder().withConfigFile(tempPath.toString()).build();
                    } finally {
                        Files.delete(tempPath);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            } else {
                kc = KeycloakAuthzClient.builder().build();
            }
        }
    }
}