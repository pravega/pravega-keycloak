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

import io.pravega.shared.security.auth.Credentials;
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
    private final String keycloakJsonString;

    public PravegaKeycloakCredentials() {
        init();
        keycloakJsonString = null;
        LOG.info("Loaded Keycloak Credentials");
    }

    public PravegaKeycloakCredentials(final String keycloakJsonString) {
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
                kc = KeycloakAuthzClient.builder().withConfigString(keycloakJsonString).build();
            } else {
                kc = KeycloakAuthzClient.builder().build();
            }
        }
    }
}
