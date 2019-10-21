package io.pravega.keycloak.client;

/**
 * Represents a problem that occurred during the authentication phase (obtaining an access token).
 * More specifically, we know we were able to connect to keycloak and the http error code was 400.
 * ( Strangely, things like providing a bad client secret result in a 400 error )
 */
public class KeycloakAuthenticationException extends RuntimeException {

    public KeycloakAuthenticationException(Throwable e) {
        super(e);
    }
}
