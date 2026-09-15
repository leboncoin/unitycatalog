package io.unitycatalog.spark.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.unitycatalog.spark.auth.catalog.AuthConfigs;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

public class AuthConfigUtilsTest {

  @Test
  public void stripsTheAuthPrefix() {
    Map<String, String> options = new HashMap<>();
    options.put("auth.type", AuthConfigs.OIDC_TYPE_VALUE);
    options.put("auth.oidc.uri", "https://example.com/oidc/v1/token");
    options.put("auth.oidc.clientId", "client-id");
    options.put("auth.oidc.tokenFilePath", "/var/run/secrets/token");
    options.put("uri", "https://example.com");

    Map<String, String> configs = AuthConfigUtils.buildAuthConfigs(options);

    assertThat(configs)
        .containsEntry(AuthConfigs.TYPE, AuthConfigs.OIDC_TYPE_VALUE)
        .containsEntry(AuthConfigs.OIDC_URI, "https://example.com/oidc/v1/token")
        .containsEntry(AuthConfigs.OIDC_CLIENT_ID, "client-id")
        .containsEntry(AuthConfigs.OIDC_TOKEN_FILE_PATH, "/var/run/secrets/token")
        .doesNotContainKey("uri");
  }

  @Test
  public void infersStaticTypeFromTheLegacyTokenKey() {
    Map<String, String> options = new HashMap<>();
    options.put(AuthConfigs.STATIC_TOKEN, "static-token");

    Map<String, String> configs = AuthConfigUtils.buildAuthConfigs(options);

    assertThat(configs)
        .containsEntry(AuthConfigs.TYPE, AuthConfigs.STATIC_TYPE_VALUE)
        .containsEntry(AuthConfigs.STATIC_TOKEN, "static-token");
  }

  @Test
  public void infersOAuthTypeFromTheLegacyUnprefixedKeys() {
    Map<String, String> options = new HashMap<>();
    options.put(AuthConfigs.OAUTH_URI, "https://example.com/oidc/v1/token");
    options.put(AuthConfigs.OAUTH_CLIENT_ID, "client-id");
    options.put(AuthConfigs.OAUTH_CLIENT_SECRET, "client-secret");

    Map<String, String> configs = AuthConfigUtils.buildAuthConfigs(options);

    assertThat(configs)
        .containsEntry(AuthConfigs.TYPE, AuthConfigs.OAUTH_TYPE_VALUE)
        .containsEntry(AuthConfigs.OAUTH_CLIENT_ID, "client-id");
  }

  @Test
  public void infersOidcTypeFromTheLegacyUnprefixedKeys() {
    Map<String, String> options = new HashMap<>();
    options.put(AuthConfigs.OIDC_URI, "https://example.com/oidc/v1/token");
    options.put(AuthConfigs.OIDC_CLIENT_ID, "client-id");
    options.put(AuthConfigs.OIDC_TOKEN_FILE_PATH, "/var/run/secrets/token");

    Map<String, String> configs = AuthConfigUtils.buildAuthConfigs(options);

    assertThat(configs)
        .containsEntry(AuthConfigs.TYPE, AuthConfigs.OIDC_TYPE_VALUE)
        .containsEntry(AuthConfigs.OIDC_TOKEN_FILE_PATH, "/var/run/secrets/token");
  }

  @Test
  public void anExplicitTypeWinsOverTheInferredOne() {
    Map<String, String> options = new HashMap<>();
    options.put("auth.type", AuthConfigs.OIDC_TYPE_VALUE);
    options.put("auth.oidc.uri", "https://example.com/oidc/v1/token");
    options.put("auth.oidc.clientId", "client-id");
    options.put("auth.oidc.tokenFilePath", "/var/run/secrets/token");
    options.put(AuthConfigs.OAUTH_URI, "https://example.com/oidc/v1/token");

    Map<String, String> configs = AuthConfigUtils.buildAuthConfigs(options);

    assertThat(configs).containsEntry(AuthConfigs.TYPE, AuthConfigs.OIDC_TYPE_VALUE);
  }

  @Test
  public void rejectsATokenConfiguredTwice() {
    Map<String, String> options = new HashMap<>();
    options.put(AuthConfigs.STATIC_TOKEN, "legacy-token");
    options.put("auth.token", "new-style-token");

    assertThatThrownBy(() -> AuthConfigUtils.buildAuthConfigs(options))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Static token was configured twice");
  }

  @Test
  public void rejectsAnOidcKeyConfiguredTwice() {
    Map<String, String> options = new HashMap<>();
    options.put(AuthConfigs.OIDC_CLIENT_ID, "legacy-client-id");
    options.put("auth.oidc.clientId", "new-style-client-id");

    assertThatThrownBy(() -> AuthConfigUtils.buildAuthConfigs(options))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("was configured twice");
  }

  @Test
  public void yieldsNoTypeWhenNoAuthIsConfigured() {
    Map<String, String> options = new HashMap<>();
    options.put("uri", "https://example.com");

    Map<String, String> configs = AuthConfigUtils.buildAuthConfigs(options);

    // UCSingleCatalog keys off the absence of `type` to skip installing an interceptor, which is
    // how an unauthenticated local metastore keeps working.
    assertThat(configs).doesNotContainKey(AuthConfigs.TYPE);
  }

  @Test
  public void keysAreCaseInsensitive() {
    Map<String, String> options = new HashMap<>();
    options.put("auth.type", AuthConfigs.OIDC_TYPE_VALUE);
    options.put("auth.oidc.clientid", "client-id");

    Map<String, String> configs = AuthConfigUtils.buildAuthConfigs(options);

    // Spark lowercases catalog option keys, so the returned map must not be case-sensitive.
    assertThat(configs.get(AuthConfigs.OIDC_CLIENT_ID)).isEqualTo("client-id");
  }

  @Test
  public void treatsAnEmptyValueAsUnset() {
    Map<String, String> options = new HashMap<>();
    // Spark hands over a declared key even when its value is blank, e.g. an unauthenticated local
    // metastore. That must leave the catalog unauthenticated, not select a provider.
    options.put(AuthConfigs.STATIC_TOKEN, "");

    Map<String, String> configs = AuthConfigUtils.buildAuthConfigs(options);

    assertThat(configs).doesNotContainKey(AuthConfigs.TYPE);
  }

  @Test
  public void treatsAnEmptyPrefixedValueAsUnset() {
    Map<String, String> options = new HashMap<>();
    options.put("auth.token", "   ");

    Map<String, String> configs = AuthConfigUtils.buildAuthConfigs(options);

    assertThat(configs).doesNotContainKey(AuthConfigs.TYPE);
  }

  @Test
  public void blankLegacyKeysDoNotInferAType() {
    Map<String, String> options = new HashMap<>();
    options.put(AuthConfigs.OAUTH_URI, "");
    options.put(AuthConfigs.OAUTH_CLIENT_ID, "");
    options.put(AuthConfigs.OAUTH_CLIENT_SECRET, "");

    Map<String, String> configs = AuthConfigUtils.buildAuthConfigs(options);

    assertThat(configs).doesNotContainKey(AuthConfigs.TYPE);
  }
}
