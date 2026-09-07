package io.unitycatalog.spark.auth.catalog;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import org.sparkproject.guava.base.Preconditions;

/**
 * Internal class - not intended for direct use.
 *
 * <p>Token provider for OIDC workload identity federation: reads an OIDC token from a file and
 * exchanges it for a Unity Catalog access token (RFC 8693 token exchange). Nothing secret is
 * stored, so there is no client secret to rotate; the caller is identified by its {@code
 * oidc.clientId} plus the trust the server places in the token issuer.
 *
 * <p>Intended for Kubernetes workloads, where the file is a projected service account token.
 * Cached and renewed {@link #DEFAULT_LEAD_RENEWAL_TIME_SECONDS} seconds before expiration,
 * thread-safe via double-checked locking, like {@link OAuthUCTokenProvider}.
 *
 * <p>lbc addition, with no 0.3.x counterpart yet. It follows the same provider contract, so {@link
 * #configs()} carries no secret and can safely cross a serialization boundary: only the token file
 * path travels, and the file itself is read wherever the provider is rebuilt.
 */
class FileOidcUCTokenProvider implements UCTokenProvider {
  private static final long DEFAULT_LEAD_RENEWAL_TIME_SECONDS = 30L;
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private static final String GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
  private static final String SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt";

  private String oidcUri;
  private String clientId;
  private String tokenFilePath;
  private long leadRenewalTimeSeconds;
  private HttpClient httpClient;
  private Supplier<Instant> clock;

  private volatile TempToken tempToken;

  FileOidcUCTokenProvider() {}

  // Package-private constructor for testing with custom dependencies.
  FileOidcUCTokenProvider(
      String oidcUri,
      String clientId,
      String tokenFilePath,
      long leadRenewalTimeSeconds,
      HttpClient httpClient,
      Supplier<Instant> clock) {
    Preconditions.checkNotNull(oidcUri, "OIDC URI must not be null");
    Preconditions.checkNotNull(clientId, "OIDC client ID must not be null");
    Preconditions.checkNotNull(tokenFilePath, "OIDC token file path must not be null");
    Preconditions.checkArgument(
        leadRenewalTimeSeconds >= 0,
        "Lead renewal time must be non-negative, but got %s",
        leadRenewalTimeSeconds);
    Preconditions.checkNotNull(httpClient, "HTTP client must not be null");
    Preconditions.checkNotNull(clock, "Clock must not be null");

    this.oidcUri = oidcUri;
    this.clientId = clientId;
    this.tokenFilePath = tokenFilePath;
    this.leadRenewalTimeSeconds = leadRenewalTimeSeconds;
    this.httpClient = httpClient;
    this.clock = clock;
  }

  @Override
  public void initialize(Map<String, String> configs) {
    String oidcUri = configs.get(AuthConfigs.OIDC_URI);
    Preconditions.checkArgument(
        oidcUri != null && !oidcUri.isEmpty(),
        "Configuration key '%s' is missing or empty",
        AuthConfigs.OIDC_URI);
    this.oidcUri = oidcUri;

    String clientId = configs.get(AuthConfigs.OIDC_CLIENT_ID);
    Preconditions.checkArgument(
        clientId != null && !clientId.isEmpty(),
        "Configuration key '%s' is missing or empty",
        AuthConfigs.OIDC_CLIENT_ID);
    this.clientId = clientId;

    String tokenFilePath = configs.get(AuthConfigs.OIDC_TOKEN_FILE_PATH);
    Preconditions.checkArgument(
        tokenFilePath != null && !tokenFilePath.isEmpty(),
        "Configuration key '%s' is missing or empty",
        AuthConfigs.OIDC_TOKEN_FILE_PATH);
    this.tokenFilePath = tokenFilePath;

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
    configs.put(AuthConfigs.TYPE, AuthConfigs.OIDC_TYPE_VALUE);
    configs.put(AuthConfigs.OIDC_URI, oidcUri);
    configs.put(AuthConfigs.OIDC_CLIENT_ID, clientId);
    configs.put(AuthConfigs.OIDC_TOKEN_FILE_PATH, tokenFilePath);
    return configs;
  }

  private TempToken renewToken() {
    try {
      // Re-read on every renewal: kubelet rotates the projected token, so a token read once at
      // initialization would expire mid-session.
      String subjectToken = readSubjectToken();

      String formData =
          "grant_type="
              + encode(GRANT_TYPE)
              + "&subject_token_type="
              + encode(SUBJECT_TOKEN_TYPE)
              + "&subject_token="
              + encode(subjectToken)
              + "&client_id="
              + encode(clientId)
              + "&scope=all-apis";

      // No Authorization header: the subject token is the proof, there is no secret to present.
      HttpRequest request =
          HttpRequest.newBuilder()
              .uri(URI.create(oidcUri))
              .header("Content-Type", "application/x-www-form-urlencoded")
              .POST(HttpRequest.BodyPublishers.ofString(formData))
              .build();

      HttpResponse<String> response =
          httpClient.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() != 200) {
        throw new IOException(
            String.format(
                "Failed to exchange OIDC token. HTTP status: %d, Response: %s",
                response.statusCode(), response.body()));
      }

      JsonNode jsonNode = OBJECT_MAPPER.readTree(response.body());
      String accessToken = jsonNode.get("access_token").asText();
      long expiresInSeconds = jsonNode.get("expires_in").asLong();

      return new TempToken(accessToken, clock.get().plusSeconds(expiresInSeconds));
    } catch (Exception e) {
      throw new RuntimeException("Failed to renew OIDC federated token", e);
    }
  }

  private String readSubjectToken() throws IOException {
    Path path = Paths.get(tokenFilePath);
    if (!Files.isRegularFile(path)) {
      throw new IOException(
          String.format(
              "OIDC token file %s does not exist. Expected a projected service account token",
              tokenFilePath));
    }
    String token = new String(Files.readAllBytes(path), StandardCharsets.UTF_8).trim();
    if (token.isEmpty()) {
      throw new IOException(String.format("OIDC token file %s is empty", tokenFilePath));
    }
    return token;
  }

  private static String encode(String value) {
    try {
      return URLEncoder.encode(value, StandardCharsets.UTF_8.name());
    } catch (java.io.UnsupportedEncodingException e) {
      throw new IllegalStateException("UTF-8 is always supported", e);
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
