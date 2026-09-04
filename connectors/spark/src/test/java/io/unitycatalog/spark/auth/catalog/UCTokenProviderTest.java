package io.unitycatalog.spark.auth.catalog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class UCTokenProviderTest {

  private static final String PREFIX = "spark.sql.catalog.cat.";

  @Test
  public void createReturnsFixedProviderWhenTokenIsSet() {
    Map<String, String> options = new HashMap<>();
    options.put(UCTokenProvider.TOKEN, "static-token");

    UCTokenProvider provider = UCTokenProvider.create(options, PREFIX);

    assertThat(provider).isInstanceOf(FixedUCTokenProvider.class);
    assertThat(provider.accessToken()).isEqualTo("static-token");
  }

  @Test
  public void createReturnsOAuthProviderWhenAllOAuthKeysAreSet() {
    Map<String, String> options = new HashMap<>();
    options.put(UCTokenProvider.OAUTH_URI, "https://example.com/oidc/v1/token");
    options.put(UCTokenProvider.OAUTH_CLIENT_ID, "client-id");
    options.put(UCTokenProvider.OAUTH_CLIENT_SECRET, "client-secret");

    UCTokenProvider provider = UCTokenProvider.create(options, PREFIX);

    assertThat(provider).isInstanceOf(OAuthUCTokenProvider.class);
  }

  @Test
  public void createReturnsFileOidcProviderWhenAllOidcKeysAreSet() {
    Map<String, String> options = new HashMap<>();
    options.put(UCTokenProvider.OIDC_URI, "https://example.com/oidc/v1/token");
    options.put(UCTokenProvider.OIDC_CLIENT_ID, "client-id");
    options.put(UCTokenProvider.OIDC_TOKEN_FILE_PATH, "/var/run/secrets/token");

    UCTokenProvider provider = UCTokenProvider.create(options, PREFIX);

    assertThat(provider).isInstanceOf(FileOidcUCTokenProvider.class);
  }

  @Test
  public void fixedProviderTakesPrecedenceOverOidc() {
    Map<String, String> options = new HashMap<>();
    options.put(UCTokenProvider.TOKEN, "static-token");
    options.put(UCTokenProvider.OIDC_URI, "https://example.com/oidc/v1/token");
    options.put(UCTokenProvider.OIDC_CLIENT_ID, "client-id");
    options.put(UCTokenProvider.OIDC_TOKEN_FILE_PATH, "/var/run/secrets/token");

    UCTokenProvider provider = UCTokenProvider.create(options, PREFIX);

    assertThat(provider).isInstanceOf(FixedUCTokenProvider.class);
  }

  @Test
  public void oidcTakesPrecedenceOverOAuth() {
    Map<String, String> options = new HashMap<>();
    options.put(UCTokenProvider.OIDC_URI, "https://example.com/oidc/v1/token");
    options.put(UCTokenProvider.OIDC_CLIENT_ID, "client-id");
    options.put(UCTokenProvider.OIDC_TOKEN_FILE_PATH, "/var/run/secrets/token");
    options.put(UCTokenProvider.OAUTH_URI, "https://example.com/oidc/v1/token");
    options.put(UCTokenProvider.OAUTH_CLIENT_ID, "client-id");
    options.put(UCTokenProvider.OAUTH_CLIENT_SECRET, "client-secret");

    UCTokenProvider provider = UCTokenProvider.create(options, PREFIX);

    assertThat(provider).isInstanceOf(FileOidcUCTokenProvider.class);
  }

  @Test
  public void createFailsOnIncompleteOidcConfig() {
    Map<String, String> options = new HashMap<>();
    options.put(UCTokenProvider.OIDC_URI, "https://example.com/oidc/v1/token");
    options.put(UCTokenProvider.OIDC_CLIENT_ID, "client-id");

    assertThatThrownBy(() -> UCTokenProvider.create(options, PREFIX))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Incomplete OIDC configuration");
  }

  @Test
  public void fixedProviderTakesPrecedenceOverOAuth() {
    Map<String, String> options = new HashMap<>();
    options.put(UCTokenProvider.TOKEN, "static-token");
    options.put(UCTokenProvider.OAUTH_URI, "https://example.com/oidc/v1/token");
    options.put(UCTokenProvider.OAUTH_CLIENT_ID, "client-id");
    options.put(UCTokenProvider.OAUTH_CLIENT_SECRET, "client-secret");

    UCTokenProvider provider = UCTokenProvider.create(options, PREFIX);

    assertThat(provider).isInstanceOf(FixedUCTokenProvider.class);
  }

  @Test
  public void createFailsOnIncompleteOAuthConfig() {
    Map<String, String> options = new HashMap<>();
    options.put(UCTokenProvider.OAUTH_URI, "https://example.com/oidc/v1/token");
    options.put(UCTokenProvider.OAUTH_CLIENT_ID, "client-id");

    assertThatThrownBy(() -> UCTokenProvider.create(options, PREFIX))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Incomplete OAuth configuration");
  }

  @Test
  public void createFailsWhenNoAuthConfig() {
    assertThatThrownBy(() -> UCTokenProvider.create(new HashMap<>(), PREFIX))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Cannot determine UC authentication configuration");
  }
}
