package io.pravega.keycloak.client;

import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.Optional;

/**
 * A factory for {@link KeycloakDeployment} for adapter configuration purposes.
 * <p>
 * The following methods are attempted, in order, to load a Keycloak adapter configuration:
 * 1. an explicit file location pointing to a Keycloak adapter configuration file
 * 2. the default location /var/run/secrets/keycloak/service-account.json
 * 3. an environment variable pointing to the location of an adapter configuration file
 */
public class KeycloakDeploymentResolver {
    private static final Logger LOG = LoggerFactory.getLogger(KeycloakDeploymentResolver.class);

    public static final String DEFAULT_KEYCLOAK_SVC_CREDS_FILE = "/var/run/secrets/keycloak/service-account.json";
    public static final String ENV_KEYCLOAK_SVC_CREDS_FILE = "KEYCLOAK_SERVICE_ACCOUNT_FILE";

    /**
     * Constructs a {@link KeycloakDeployment} by looking in the default location or and env. variable pointing to a file
     *
     * @return
     */
    public static Optional<KeycloakDeployment> resolve() {
        return resolve(null);
    }

    /**
     * Constructs a {@link KeycloakDeployment} by loading a Keycloak adapter configuration from
     * the given location, from a location given by an environment variable, or from a default location.
     *
     * @return a {@link KeycloakDeployment} if found.
     */
    public static Optional<KeycloakDeployment> resolve(String fileLocation) {
        Optional<Path> configPath = getConfigFile(System.getenv(), fileLocation, ENV_KEYCLOAK_SVC_CREDS_FILE, DEFAULT_KEYCLOAK_SVC_CREDS_FILE);
        if (!configPath.isPresent()) {
            LOG.info("Keycloak adapter config not found");
            return Optional.empty();
        }
        try (InputStream stream = Files.newInputStream(configPath.get())) {
            LOG.info("Loaded Keycloak adapter config: {}", configPath.get());
            return Optional.of(KeycloakDeploymentBuilder.build(stream));
        } catch (Exception e) {
            throw new IllegalStateException("Unable to resolve the Keycloak adapter config", e);
        }
    }

    /**
     * Returns an Optional of a Path given three inputs, evaluated in order. Each one is tested as being not null and
     * corresponding to an existing file.  If all three fail, an Optional.empty() is returned.
     *
     * @param explicitLocation explicit path pointing to a file
     * @param locationEnv      choice based on a location pointed by this supplied env variable
     * @param defaultLocation  default choice if the first location is not provided
     */
    static Optional<Path> getConfigFile(Map<String, String> envs, String explicitLocation, String locationEnv, String defaultLocation) {
        return pathIfExists(explicitLocation)
                .or(() -> pathIfExists(envs.get(locationEnv)))
                .or(() -> pathIfExists(defaultLocation));
    }

    private static Optional<Path> pathIfExists(String pathStr) {
        return Optional.ofNullable(pathStr).map(Paths::get).filter(Files::isReadable);
    }
}
