package io.pravega.keycloak.client;

/**
 * Represents a problem that occurred during the authorization phase (obtaining an RPT for a target audience).
 * More specifically, we know we were able to connect to keycloak and the http error code was 400.
 * ( Strangely, things like providing a bad audience or talking to a client that doesn't have authz enabled
 * result in a 400 error )
 */
public class KeycloakAuthorizationException extends RuntimeException {
    public KeycloakAuthorizationException(Throwable e) {
        super(e);
    }
}
