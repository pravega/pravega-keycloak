package io.pravega.keycloak.client.helpers;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.rotation.PublicKeyLocator;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.representations.AccessToken;

import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;

import static org.keycloak.OAuth2Constants.JWT;

/**
 * Issues signed Keycloak access tokens based on a generated keypair for test purposes.
 */
public class AccessTokenIssuer implements PublicKeyLocator {

    public static final String ISSUER = "http://localhost/realms/test";

    private final KeyPair issuerKeyPair;

    public AccessTokenIssuer() {
        issuerKeyPair = KeyUtils.generateRsaKeyPair(2048);
    }

    /**
     * Issues a signed token.
     *
     * @param accessToken  the access token details.
     * @param forceExpired if true forces creation of an expired token
     * @return a signed token string.
     */
    public String issue(AccessToken accessToken, boolean forceExpired) {
        accessToken.issuedNow();
        accessToken.issuer(ISSUER);
        if (forceExpired) {
            accessToken.expiration(0);
        } else {
            accessToken.expiration(computeExpiration(accessToken, Duration.ofMinutes(60)));
        }

        return new JWSBuilder()
                .type(JWT)
                .kid(KeyUtils.createKeyId(issuerKeyPair.getPublic()))
                .jsonContent(accessToken)
                .rsa256(issuerKeyPair.getPrivate());
    }

    public String issue(AccessToken accessToken) {
        return issue(accessToken, false);
    }

    /**
     * Computes the "expiresAt" timestamp based on the desired expiration duration
     * and when the token was issued
     *
     * @param token
     * @param expiration
     * @return
     */
    private static int computeExpiration(AccessToken token, Duration expiration) {
        int issuedAt = token.getIssuedAt();
        int expirationInSeconds = (int) expiration.toMillis() / 1000;
        return issuedAt + expirationInSeconds;
    }


    @Override
    public void reset(KeycloakDeployment deployment) {
    }

    /**
     * Gets the public key associated with the issuer.
     */
    @Override
    public PublicKey getPublicKey(String kid, KeycloakDeployment deployment) {
        if (KeyUtils.createKeyId(issuerKeyPair.getPublic()).equals(kid)) {
            return issuerKeyPair.getPublic();
        }
        return null;
    }
}
