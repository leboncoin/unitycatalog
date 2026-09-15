package io.unitycatalog.spark.auth.catalog;

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
}
