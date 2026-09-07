package io.unitycatalog.spark.auth.catalog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import org.sparkproject.guava.base.Preconditions;

/**
 * Internal class - not intended for direct use.
 *
 * <p>OAuth-based token provider that fetches and automatically renews access tokens using the OAuth
 * 2.0 client credentials flow (machine-to-machine).
 *
 * <p>Backport of the 0.3.x {@code OAuthTokenProvider} to the 0.2.x connector. The 0.3.x version
 * relies on {@code RetryingApiClient}/{@code Clock}, neither of which exists in 0.2.x; here the
 * request uses the JDK {@link HttpClient} and {@link Instant#now()} directly, so the exchange is not
 * retried. Behaviour is otherwise identical: the token is cached and renewed {@link
 * #DEFAULT_LEAD_RENEWAL_TIME_SECONDS} seconds before expiration, thread-safe via double-checked
 * locking.
 */
class OAuthUCTokenProvider implements UCTokenProvider {
  private static final long DEFAULT_LEAD_RENEWAL_TIME_SECONDS = 30L;
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private String oauthUri;
  private String oauthClientId;
  private String oauthClientSecret;
  private long leadRenewalTimeSeconds;
  private HttpClient httpClient;
  private Supplier<Instant> clock;

  private volatile TempToken tempToken;

  OAuthUCTokenProvider() {}

  // Package-private constructor for testing with custom dependencies.
  OAuthUCTokenProvider(
      String oauthUri,
      String oauthClientId,
      String oauthClientSecret,
      long leadRenewalTimeSeconds,
      HttpClient httpClient,
      Supplier<Instant> clock) {
    Preconditions.checkNotNull(oauthUri, "OAuth URI must not be null");
    Preconditions.checkNotNull(oauthClientId, "OAuth client ID must not be null");
    Preconditions.checkNotNull(oauthClientSecret, "OAuth client secret must not be null");
    Preconditions.checkArgument(
        leadRenewalTimeSeconds >= 0,
        "Lead renewal time must be non-negative, but got %s",
        leadRenewalTimeSeconds);
    Preconditions.checkNotNull(httpClient, "HTTP client must not be null");
    Preconditions.checkNotNull(clock, "Clock must not be null");

    this.oauthUri = oauthUri;
    this.oauthClientId = oauthClientId;
    this.oauthClientSecret = oauthClientSecret;
    this.leadRenewalTimeSeconds = leadRenewalTimeSeconds;
    this.httpClient = httpClient;
    this.clock = clock;
  }

  @Override
  public void initialize(Map<String, String> configs) {
    String oauthUri = configs.get(AuthConfigs.OAUTH_URI);
    Preconditions.checkArgument(
        oauthUri != null && !oauthUri.isEmpty(),
        "Configuration key '%s' is missing or empty",
        AuthConfigs.OAUTH_URI);
    this.oauthUri = oauthUri;

    String oauthClientId = configs.get(AuthConfigs.OAUTH_CLIENT_ID);
    Preconditions.checkArgument(
        oauthClientId != null && !oauthClientId.isEmpty(),
        "Configuration key '%s' is missing or empty",
        AuthConfigs.OAUTH_CLIENT_ID);
    this.oauthClientId = oauthClientId;

    String oauthClientSecret = configs.get(AuthConfigs.OAUTH_CLIENT_SECRET);
    Preconditions.checkArgument(
        oauthClientSecret != null && !oauthClientSecret.isEmpty(),
        "Configuration key '%s' is missing or empty",
        AuthConfigs.OAUTH_CLIENT_SECRET);
    this.oauthClientSecret = oauthClientSecret;

    this.leadRenewalTimeSeconds = DEFAULT_LEAD_RENEWAL_TIME_SECONDS;
    this.httpClient = HttpClient.newHttpClient();
    this.clock = Instant::now;
  }

  @Override
  public String accessToken() {
    if (tempToken == null || tempToken.isReadyToRenew()) {
      synchronized (this) {
        if (tempToken == null || tempToken.isReadyToRenew()) {
          tempToken = renewToken();
        }
      }
    }
    return tempToken.token();
  }

  @Override
  public Map<String, String> configs() {
    Map<String, String> configs = new HashMap<>();
    configs.put(AuthConfigs.TYPE, AuthConfigs.OAUTH_TYPE_VALUE);
    configs.put(AuthConfigs.OAUTH_URI, oauthUri);
    configs.put(AuthConfigs.OAUTH_CLIENT_ID, oauthClientId);
    configs.put(AuthConfigs.OAUTH_CLIENT_SECRET, oauthClientSecret);
    return configs;
  }

  private TempToken renewToken() {
    try {
      // Basic auth header from clientId:clientSecret.
      String credentials = String.format("%s:%s", oauthClientId, oauthClientSecret);
      String encodedCredentials =
          Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));

      String formData = "grant_type=client_credentials&scope=all-apis";

      HttpRequest request =
          HttpRequest.newBuilder()
              .uri(URI.create(oauthUri))
              .header("Authorization", "Basic " + encodedCredentials)
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(HttpRequest.BodyPublishers.ofString(formData))
              .build();

      HttpResponse<String> response =
          httpClient.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() != 200) {
        throw new IOException(
            String.format(
                "Failed to fetch OAuth token. HTTP status: %d, Response: %s",
                response.statusCode(), response.body()));
      }

      JsonNode jsonNode = OBJECT_MAPPER.readTree(response.body());
      String accessToken = jsonNode.get("access_token").asText();
      long expiresInSeconds = jsonNode.get("expires_in").asLong();

      return new TempToken(accessToken, clock.get().plusSeconds(expiresInSeconds));
    } catch (Exception e) {
      throw new RuntimeException("Failed to renew OAuth token", e);
    }
  }

  private class TempToken {
    private final String token;
    private final Instant expirationTime;

    TempToken(String token, Instant expirationTime) {
      this.token = token;
      this.expirationTime = expirationTime;
    }

    String token() {
      return token;
    }

    boolean isReadyToRenew() {
      Instant renewalTime = expirationTime.minusSeconds(leadRenewalTimeSeconds);
      return clock.get().isAfter(renewalTime);
    }
  }
}
