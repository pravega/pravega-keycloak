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

/**
 * Represents a problem that occurred during the authentication phase (obtaining an access token).
 * More specifically, we know we were able to connect to keycloak and the http error code was 400.
 * ( Strangely, things like providing a bad client secret result in a 400 error )
 */
public class KeycloakAuthenticationException extends RuntimeException {
    public KeycloakAuthenticationException(Throwable e) {
        super("Authentication failure", e);
    }
}
