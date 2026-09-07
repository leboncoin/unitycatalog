package io.unitycatalog.spark.auth.catalog;

import java.util.HashMap;
import java.util.Map;
import org.sparkproject.guava.base.Preconditions;

/**
 * Internal class - not intended for direct use.
 *
 * <p>A {@link UCTokenProvider} that always returns a pre-configured static token.
 */
class FixedUCTokenProvider implements UCTokenProvider {
  private String token;

  FixedUCTokenProvider() {}

  @Override
  public void initialize(Map<String, String> configs) {
    String token = configs.get(AuthConfigs.STATIC_TOKEN);
    Preconditions.checkArgument(
        token != null && !token.isEmpty(),
        "Configuration key '%s' is missing or empty",
        AuthConfigs.STATIC_TOKEN);
    this.token = token;
  }

  @Override
  public String accessToken() {
    return token;
  }

  @Override
  public Map<String, String> configs() {
    // Not Map.of: the 0.2.x connector targets Java 11 but keeps the 0.3.x shape otherwise.
    Map<String, String> configs = new HashMap<>();
    configs.put(AuthConfigs.TYPE, AuthConfigs.STATIC_TYPE_VALUE);
    configs.put(AuthConfigs.STATIC_TOKEN, token);
    return configs;
  }
}
