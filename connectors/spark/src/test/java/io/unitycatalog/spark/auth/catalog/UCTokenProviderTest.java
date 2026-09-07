package io.unitycatalog.spark.auth.catalog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class UCTokenProviderTest {

  @Test
  public void createReturnsFixedProviderForStaticType() {
    Map<String, String> configs = new HashMap<>();
    configs.put(AuthConfigs.TYPE, AuthConfigs.STATIC_TYPE_VALUE);
    configs.put(AuthConfigs.STATIC_TOKEN, "static-token");

    UCTokenProvider provider = UCTokenProvider.create(configs);

    assertThat(provider).isInstanceOf(FixedUCTokenProvider.class);
    assertThat(provider.accessToken()).isEqualTo("static-token");
  }

  @Test
  public void createReturnsOAuthProviderForOAuthType() {
    Map<String, String> configs = new HashMap<>();
    configs.put(AuthConfigs.TYPE, AuthConfigs.OAUTH_TYPE_VALUE);
    configs.put(AuthConfigs.OAUTH_URI, "https://example.com/oidc/v1/token");
    configs.put(AuthConfigs.OAUTH_CLIENT_ID, "client-id");
    configs.put(AuthConfigs.OAUTH_CLIENT_SECRET, "client-secret");

    UCTokenProvider provider = UCTokenProvider.create(configs);

    assertThat(provider).isInstanceOf(OAuthUCTokenProvider.class);
  }

  @Test
  public void createReturnsFileOidcProviderForOidcType() {
    UCTokenProvider provider = UCTokenProvider.create(oidcConfigs());

    assertThat(provider).isInstanceOf(FileOidcUCTokenProvider.class);
  }

  @Test
  public void createInstantiatesACustomProviderByClassName() {
    Map<String, String> configs = new HashMap<>();
    configs.put(AuthConfigs.TYPE, CustomTokenProvider.class.getName());

    UCTokenProvider provider = UCTokenProvider.create(configs);

    assertThat(provider).isInstanceOf(CustomTokenProvider.class);
    assertThat(provider.accessToken()).isEqualTo("custom-token");
  }

  @Test
  public void createFailsWhenTypeIsMissing() {
    Map<String, String> configs = new HashMap<>();
    configs.put(AuthConfigs.STATIC_TOKEN, "static-token");

    assertThatThrownBy(() -> UCTokenProvider.create(configs))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Required configuration key 'type' is missing or empty");
  }

  @Test
  public void createFailsWhenACustomClassCannotBeInstantiated() {
    Map<String, String> configs = new HashMap<>();
    configs.put(AuthConfigs.TYPE, "com.example.NoSuchProvider");

    assertThatThrownBy(() -> UCTokenProvider.create(configs))
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining("Failed to instantiate custom UCTokenProvider");
  }

  @Test
  public void createFailsOnIncompleteOidcConfig() {
    Map<String, String> configs = oidcConfigs();
    configs.remove(AuthConfigs.OIDC_TOKEN_FILE_PATH);

    assertThatThrownBy(() -> UCTokenProvider.create(configs))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Configuration key 'oidc.tokenFilePath' is missing or empty");
  }

  @Test
  public void createFailsOnIncompleteOAuthConfig() {
    Map<String, String> configs = new HashMap<>();
    configs.put(AuthConfigs.TYPE, AuthConfigs.OAUTH_TYPE_VALUE);
    configs.put(AuthConfigs.OAUTH_URI, "https://example.com/oidc/v1/token");
    configs.put(AuthConfigs.OAUTH_CLIENT_ID, "client-id");

    assertThatThrownBy(() -> UCTokenProvider.create(configs))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Configuration key 'oauth.clientSecret' is missing or empty");
  }

  private static Map<String, String> oidcConfigs() {
    Map<String, String> configs = new HashMap<>();
    configs.put(AuthConfigs.TYPE, AuthConfigs.OIDC_TYPE_VALUE);
    configs.put(AuthConfigs.OIDC_URI, "https://example.com/oidc/v1/token");
    configs.put(AuthConfigs.OIDC_CLIENT_ID, "client-id");
    configs.put(AuthConfigs.OIDC_TOKEN_FILE_PATH, "/var/run/secrets/token");
    return configs;
  }

  /** Public so {@code Class.forName(...).getDeclaredConstructor().newInstance()} can reach it. */
  public static class CustomTokenProvider implements UCTokenProvider {
    @Override
    public void initialize(Map<String, String> configs) {}

    @Override
    public String accessToken() {
      return "custom-token";
    }
  }
}
