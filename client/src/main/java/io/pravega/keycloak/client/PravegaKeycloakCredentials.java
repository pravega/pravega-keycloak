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

import io.pravega.client.stream.impl.Credentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    public PravegaKeycloakCredentials() {
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
            kc = KeycloakAuthzClient.builder().build();
        }
    }
}
