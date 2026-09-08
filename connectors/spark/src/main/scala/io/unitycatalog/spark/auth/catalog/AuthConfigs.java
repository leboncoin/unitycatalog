package io.unitycatalog.spark.auth.catalog;

/**
 * Configuration keys for {@link UCTokenProvider} implementations.
 *
 * <p>Backport of the 0.3.x {@code io.unitycatalog.client.auth.AuthConfigs} to the 0.2.x connector.
 * The 0.3.x client is generated at build time here, so the constants live in the Spark module
 * instead; the key names are kept identical so a future rebase is a package move. Public rather
 * than package-private for the same reason: {@link io.unitycatalog.spark.auth.AuthConfigUtils} sits
 * in the package upstream puts it in, and reads these instead of redeclaring them.
 */
public final class AuthConfigs {
  private AuthConfigs() {}

  // Define the authentication type, where the type can be:
  // 1. static: which uses the FixedUCTokenProvider to return a pre-configured token.
  // 2. oauth: which uses the OAuthUCTokenProvider to run the client credentials flow.
  // 3. oidc: which uses the FileOidcUCTokenProvider to exchange a federated OIDC token.
  // 4. fully qualified class name of a custom UCTokenProvider implementation.
  public static final String TYPE = "type";

  // Configure keys for the static token provider.
  public static final String STATIC_TYPE_VALUE = "static";
  public static final String STATIC_TOKEN = "token";

  // Configure keys for the oauth token provider.
  public static final String OAUTH_TYPE_VALUE = "oauth";
  public static final String OAUTH_URI = "oauth.uri";
  public static final String OAUTH_CLIENT_ID = "oauth.clientId";
  public static final String OAUTH_CLIENT_SECRET = "oauth.clientSecret";

  // Configure keys for the OIDC federation token provider. lbc addition with no 0.3.x counterpart
  // yet, so the naming follows the oauth block rather than inventing a new shape.
  public static final String OIDC_TYPE_VALUE = "oidc";
  public static final String OIDC_URI = "oidc.uri";
  public static final String OIDC_CLIENT_ID = "oidc.clientId";
  public static final String OIDC_TOKEN_FILE_PATH = "oidc.tokenFilePath";
}
