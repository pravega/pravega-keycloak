package io.pravega.keycloak.client;

import io.pravega.client.stream.impl.Credentials;
import org.keycloak.adapters.KeycloakDeployment;
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

    // for testing only
    public PravegaKeycloakCredentials(KeycloakDeployment deployment) {
        kc = new KeycloakAuthzClient(deployment);
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
            kc = KeycloakAuthzClient.client();
        }
    }
}
