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
import java.util.function.Supplier;
import org.sparkproject.guava.base.Preconditions;

/**
 * OAuth-based token provider that fetches and automatically renews access tokens using the
 * OAuth 2.0 client credentials flow (machine-to-machine).
 *
 * <p>Backport of the 0.3.x {@code OAuthUCTokenProvider} to the 0.2.x connector. The 0.3.x
 * version relies on {@code RetryingApiClient}/{@code ApiClientConf}/injectable {@code Clock},
 * none of which exist in 0.2.x; here the request uses the JDK {@link HttpClient} and
 * {@link Instant#now()} directly. Behaviour is otherwise identical: token is cached and renewed
 * {@link #DEFAULT_LEAD_RENEWAL_TIME_SECONDS} seconds before expiration, thread-safe via
 * double-checked locking. The connector calls {@link #accessToken()} on every request so the
 * refreshed token propagates without re-initializing the catalog.
 */
public class OAuthUCTokenProvider implements UCTokenProvider {
  private static final long DEFAULT_LEAD_RENEWAL_TIME_SECONDS = 30L;
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final String oauthUri;
  private final String oauthClientId;
  private final String oauthClientSecret;
  private final long leadRenewalTimeSeconds;
  private final HttpClient httpClient;
  private final Supplier<Instant> clock;

  private volatile TempToken tempToken;

  public OAuthUCTokenProvider(String oauthUri, String oauthClientId, String oauthClientSecret) {
    this(oauthUri, oauthClientId, oauthClientSecret, DEFAULT_LEAD_RENEWAL_TIME_SECONDS,
        HttpClient.newHttpClient(), Instant::now);
  }

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
    Preconditions.checkArgument(leadRenewalTimeSeconds >= 0,
        "Lead renewal time must be non-negative, but got %s", leadRenewalTimeSeconds);
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

  private TempToken renewToken() {
    try {
      // Basic auth header from clientId:clientSecret.
      String credentials = String.format("%s:%s", oauthClientId, oauthClientSecret);
      String encodedCredentials = Base64.getEncoder()
          .encodeToString(credentials.getBytes(StandardCharsets.UTF_8));

      String formData = "grant_type=client_credentials&scope=all-apis";

      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(oauthUri))
          .header("Authorization", "Basic " + encodedCredentials)
          .header("Content-Type", "application/x-www-form-urlencoded")
          .POST(HttpRequest.BodyPublishers.ofString(formData))
          .build();

      HttpResponse<String> response = httpClient.send(request,
          HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() != 200) {
        throw new IOException(String.format(
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
