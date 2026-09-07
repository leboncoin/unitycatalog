package io.unitycatalog.spark.auth.catalog;

import io.unitycatalog.spark.auth.AuthConfigUtils;
import java.util.Map;
import org.sparkproject.guava.base.Preconditions;

/**
 * Interface for providing access tokens to authenticate with Unity Catalog.
 *
 * <p>Implementations:
 *
 * <ul>
 *   <li>{@link FixedUCTokenProvider} - uses a pre-configured static token
 *   <li>{@link OAuthUCTokenProvider} - obtains tokens via OAuth 2.0 client credentials flow
 *   <li>{@link FileOidcUCTokenProvider} - exchanges an OIDC token read from a file (workload
 *       identity federation), so no secret is stored
 * </ul>
 *
 * <p>Backport of the 0.3.x {@code TokenProvider} to the 0.2.x connector, including the {@code
 * type}-based dispatch. The OAuth implementation relies only on the JDK HTTP client available in
 * 0.2.x, as {@code RetryingApiClient} does not exist here.
 *
 * <p>The 0.3.x {@code configs()} accessor is deliberately left out: it exists there so an executor
 * can rebuild a provider from the Hadoop configuration and renew vended credentials, which the
 * 0.2.x connector never does. Everything here runs on the driver.
 */
public interface UCTokenProvider {

  /**
   * Initializes the token provider with configuration parameters.
   *
   * @param configs configuration map with authentication settings, keys without prefix
   * @throws IllegalArgumentException if required parameters are missing or invalid
   */
  void initialize(Map<String, String> configs);

  /** Returns the access token for Unity Catalog authentication, refreshing it when needed. */
  String accessToken();

  /**
   * Creates a token provider from a configuration map.
   *
   * <p>Dispatches on the required {@code type} key: {@code static}, {@code oauth}, {@code oidc}, or
   * the fully qualified class name of a custom {@link UCTokenProvider} implementation. Legacy
   * option shapes are normalized to a {@code type} upstream by {@link AuthConfigUtils}.
   *
   * @throws IllegalArgumentException if {@code type} is missing, or if the parameters required by
   *     the selected type are missing or invalid
   * @throws RuntimeException if a custom provider class cannot be instantiated
   */
  static UCTokenProvider create(Map<String, String> configs) {
    String authType = configs.get(AuthConfigs.TYPE);
    Preconditions.checkArgument(
        authType != null && !authType.trim().isEmpty(),
        "Required configuration key '%s' is missing or empty. "
            + "Must be 'static', 'oauth', 'oidc', or a fully qualified UCTokenProvider class name.",
        AuthConfigs.TYPE);

    UCTokenProvider tokenProvider;
    switch (authType) {
      case AuthConfigs.STATIC_TYPE_VALUE:
        tokenProvider = new FixedUCTokenProvider();
        break;

      case AuthConfigs.OAUTH_TYPE_VALUE:
        tokenProvider = new OAuthUCTokenProvider();
        break;

      case AuthConfigs.OIDC_TYPE_VALUE:
        tokenProvider = new FileOidcUCTokenProvider();
        break;

      default:
        try {
          tokenProvider =
              (UCTokenProvider) Class.forName(authType).getDeclaredConstructor().newInstance();
        } catch (Exception e) {
          throw new RuntimeException(
              String.format(
                  "Failed to instantiate custom UCTokenProvider '%s'. Ensure the class exists, "
                      + "implements UCTokenProvider, and has a public no-arg constructor.",
                  authType),
              e);
        }
        break;
    }

    tokenProvider.initialize(configs);
    return tokenProvider;
  }
}
