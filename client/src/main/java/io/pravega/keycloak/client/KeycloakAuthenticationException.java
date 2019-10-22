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
