package io.unitycatalog.spark.auth.catalog;

import static org.sparkproject.guava.base.Preconditions.checkArgument;

import java.util.Map;

/**
 * Interface for providing access tokens to authenticate with Unity Catalog.
 *
 * <p>Implementations:
 * <ul>
 *   <li>{@link FixedUCTokenProvider} - uses a pre-configured static token</li>
 *   <li>{@link OAuthUCTokenProvider} - obtains tokens via OAuth 2.0 client credentials flow</li>
 * </ul>
 *
 * <p>Backport of the 0.3.x {@code UCTokenProvider} to the 0.2.x connector: same option
 * formalism ({@code token} or {@code oauth.uri}/{@code oauth.clientId}/{@code oauth.clientSecret}),
 * but the OAuth implementation relies only on the JDK HTTP client available in 0.2.x.
 */
public interface UCTokenProvider {

  String OAUTH_URI = "oauth.uri";
  String OAUTH_CLIENT_ID = "oauth.clientId";
  String OAUTH_CLIENT_SECRET = "oauth.clientSecret";
  String TOKEN = "token";

  /** Returns the access token for Unity Catalog authentication, refreshing it when needed. */
  String accessToken();

  /**
   * Creates a token provider from catalog options (keys without prefix). Returns a
   * {@link FixedUCTokenProvider} when {@code token} is set, otherwise an
   * {@link OAuthUCTokenProvider} when the three {@code oauth.*} keys are set.
   *
   * @param optionKeyPrefix prefix prepended to option keys in error messages, e.g.
   *                        {@code "spark.sql.catalog.<catalogName>."}
   * @throws IllegalArgumentException if no complete authentication configuration is found
   */
  static UCTokenProvider create(Map<String, String> options, String optionKeyPrefix) {
    String token = options.get(TOKEN);
    if (token != null && !token.isEmpty()) {
      return new FixedUCTokenProvider(token);
    }

    String oauthUri = options.get(OAUTH_URI);
    String oauthClientId = options.get(OAUTH_CLIENT_ID);
    String oauthClientSecret = options.get(OAUTH_CLIENT_SECRET);
    if (oauthUri != null || oauthClientId != null || oauthClientSecret != null) {
      checkArgument(oauthUri != null && oauthClientId != null && oauthClientSecret != null,
          "Incomplete OAuth configuration detected. All of the keys are required: "
              + "%soauth.uri, %soauth.clientId, %soauth.clientSecret. Please ensure they are "
              + "all set.", optionKeyPrefix, optionKeyPrefix, optionKeyPrefix);
      return new OAuthUCTokenProvider(oauthUri, oauthClientId, oauthClientSecret);
    }

    throw new IllegalArgumentException(String.format("Cannot determine UC authentication "
            + "configuration from options, please set %stoken for static token authentication or "
            + "%soauth.uri, %soauth.clientId, %soauth.clientSecret for OAuth 2.0 authentication "
            + "(all three required)",
        optionKeyPrefix, optionKeyPrefix, optionKeyPrefix, optionKeyPrefix));
  }
}
