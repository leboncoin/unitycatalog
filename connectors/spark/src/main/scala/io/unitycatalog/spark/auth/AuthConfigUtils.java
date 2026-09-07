package io.unitycatalog.spark.auth;

import io.unitycatalog.spark.auth.catalog.AuthConfigs;
import java.util.HashMap;
import java.util.Map;
import org.apache.spark.sql.util.CaseInsensitiveStringMap;
import org.sparkproject.guava.base.Preconditions;

/**
 * Normalizes catalog options into the flat, {@code type}-keyed configuration map that {@code
 * UCTokenProvider.create} expects.
 *
 * <p>Backport of the 0.3.x {@code AuthConfigUtils}, extended with the legacy {@code oauth.*} shape:
 * this connector shipped those keys before the {@code auth.} prefix existed, so both are accepted.
 */
public class AuthConfigUtils {
  private static final String AUTH_PREFIX = "auth.";

  private AuthConfigUtils() {}

  public static Map<String, String> buildAuthConfigs(Map<String, String> configs) {
    Map<String, String> newConfigs = new HashMap<>();

    for (Map.Entry<String, String> e : configs.entrySet()) {
      if (e.getKey().startsWith(AUTH_PREFIX)) {
        // Remove the 'auth.' prefix from the key and add the normalized key-value pair.
        String newKey = e.getKey().substring(AUTH_PREFIX.length()).trim();
        if (!newKey.isEmpty()) {
          newConfigs.put(newKey, e.getValue());
        }
      }
    }

    // Unity Catalog versions 0.3.0 and earlier did not use the 'auth.token' key. To maintain
    // backward compatibility, we also copy the legacy 'token' key directly into the new config map.
    String token = configs.get(AuthConfigs.STATIC_TOKEN);
    if (token != null) {
      Preconditions.checkArgument(
          !newConfigs.containsKey(AuthConfigs.STATIC_TOKEN),
          "Static token was configured twice, choose only one: 'token' (legacy) or 'auth.token' (new-style).");

      newConfigs.put(AuthConfigs.TYPE, AuthConfigs.STATIC_TYPE_VALUE);
      newConfigs.put(AuthConfigs.STATIC_TOKEN, token);
    }

    // Same treatment for the un-prefixed oauth keys, which this fork shipped before adopting the
    // 0.3.x formalism. Infers the type so existing catalog configs keep working untouched.
    copyLegacyGroup(
        configs,
        newConfigs,
        AuthConfigs.OAUTH_TYPE_VALUE,
        AuthConfigs.OAUTH_URI,
        AuthConfigs.OAUTH_CLIENT_ID,
        AuthConfigs.OAUTH_CLIENT_SECRET);

    copyLegacyGroup(
        configs,
        newConfigs,
        AuthConfigs.OIDC_TYPE_VALUE,
        AuthConfigs.OIDC_URI,
        AuthConfigs.OIDC_CLIENT_ID,
        AuthConfigs.OIDC_TOKEN_FILE_PATH);

    return new CaseInsensitiveStringMap(newConfigs);
  }

  private static void copyLegacyGroup(
      Map<String, String> configs,
      Map<String, String> newConfigs,
      String typeValue,
      String... keys) {
    boolean anyLegacy = false;
    for (String key : keys) {
      if (configs.get(key) != null) {
        anyLegacy = true;
        break;
      }
    }
    if (!anyLegacy) {
      return;
    }

    for (String key : keys) {
      String value = configs.get(key);
      if (value == null) {
        continue;
      }
      Preconditions.checkArgument(
          !newConfigs.containsKey(key),
          "'%s' was configured twice, choose only one: '%s' (legacy) or 'auth.%s' (new-style).",
          key,
          key,
          key);
      newConfigs.put(key, value);
    }

    if (!newConfigs.containsKey(AuthConfigs.TYPE)) {
      newConfigs.put(AuthConfigs.TYPE, typeValue);
    }
  }
}
