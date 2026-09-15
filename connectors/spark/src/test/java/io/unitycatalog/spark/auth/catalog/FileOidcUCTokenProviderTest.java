package io.unitycatalog.spark.auth.catalog;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Flow;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class FileOidcUCTokenProviderTest {

  private static final String URI = "https://example.com/oidc/v1/token";
  private static final String CLIENT_ID = "client-id";

  @TempDir Path tempDir;

  private HttpClient httpClient;
  private Instant now;

  @BeforeEach
  public void setUp() {
    httpClient = mock(HttpClient.class);
    now = Instant.parse("2026-01-01T00:00:00Z");
  }

  @Test
  public void exchangesTheTokenReadFromFile() throws Exception {
    Path tokenFile = writeToken("header.payload.signature");
    stubResponse(200, "{\"access_token\":\"exchanged\",\"expires_in\":3600}");

    FileOidcUCTokenProvider provider = provider(tokenFile);

    assertThat(provider.accessToken()).isEqualTo("exchanged");

    String body = capturedBody();
    assertThat(body)
        .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange");
    assertThat(body).contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt");
    assertThat(body).contains("subject_token=header.payload.signature");
    assertThat(body).contains("client_id=client-id");
    assertThat(body).contains("scope=all-apis");
    assertThat(capturedRequest().headers().firstValue("Authorization")).isEmpty();
  }

  @Test
  public void cachesTheTokenWhileItIsStillValid() throws Exception {
    Path tokenFile = writeToken("header.payload.signature");
    stubResponse(200, "{\"access_token\":\"exchanged\",\"expires_in\":3600}");

    FileOidcUCTokenProvider provider = provider(tokenFile);

    provider.accessToken();
    provider.accessToken();

    verify(httpClient, times(1)).send(any(HttpRequest.class), any());
  }

  @Test
  public void rereadsTheFileAndExchangesAgainOnceExpired() throws Exception {
    Path tokenFile = writeToken("first.jwt.value");
    stubResponse(200, "{\"access_token\":\"first\",\"expires_in\":3600}");

    FileOidcUCTokenProvider provider = provider(tokenFile);
    assertThat(provider.accessToken()).isEqualTo("first");

    // kubelet rotated the projected token, and the cached access token is past its renewal lead.
    writeToken("second.jwt.value");
    stubResponse(200, "{\"access_token\":\"second\",\"expires_in\":3600}");
    now = now.plusSeconds(3600);

    assertThat(provider.accessToken()).isEqualTo("second");
    assertThat(capturedBody()).contains("subject_token=second.jwt.value");
    verify(httpClient, times(2)).send(any(HttpRequest.class), any());
  }

  @Test
  public void failsWhenTheResponseIsNotSuccessful() throws Exception {
    Path tokenFile = writeToken("header.payload.signature");
    stubResponse(400, "{\"error\":\"invalid_grant\"}");

    FileOidcUCTokenProvider provider = provider(tokenFile);

    assertThatThrownBy(provider::accessToken)
        .isInstanceOf(RuntimeException.class)
        .hasMessageContaining("Failed to renew OIDC federated token")
        .hasRootCauseMessage(
            "Failed to exchange OIDC token. HTTP status: 400, Response: {\"error\":\"invalid_grant\"}");
  }

  @Test
  public void failsWhenTheTokenFileIsMissing() {
    FileOidcUCTokenProvider provider = provider(tempDir.resolve("absent"));

    assertThatThrownBy(provider::accessToken)
        .isInstanceOf(RuntimeException.class)
        .hasRootCauseInstanceOf(IOException.class)
        .rootCause()
        .hasMessageContaining("does not exist");
  }

  @Test
  public void failsWhenTheTokenFileIsEmpty() throws Exception {
    Path tokenFile = writeToken("   \n");

    FileOidcUCTokenProvider provider = provider(tokenFile);

    assertThatThrownBy(provider::accessToken)
        .isInstanceOf(RuntimeException.class)
        .hasRootCauseInstanceOf(IOException.class)
        .rootCause()
        .hasMessageContaining("is empty");
  }

  private FileOidcUCTokenProvider provider(Path tokenFile) {
    Supplier<Instant> clock = () -> now;
    return new FileOidcUCTokenProvider(
        URI, CLIENT_ID, tokenFile.toString(), 30L, httpClient, clock);
  }

  private Path writeToken(String content) throws IOException {
    Path tokenFile = tempDir.resolve("token");
    Files.write(tokenFile, content.getBytes(StandardCharsets.UTF_8));
    return tokenFile;
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private void stubResponse(int statusCode, String body) throws Exception {
    HttpResponse<String> response = mock(HttpResponse.class);
    when(response.statusCode()).thenReturn(statusCode);
    when(response.body()).thenReturn(body);
    when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
        .thenReturn((HttpResponse) response);
  }

  private HttpRequest capturedRequest() throws Exception {
    org.mockito.ArgumentCaptor<HttpRequest> captor =
        org.mockito.ArgumentCaptor.forClass(HttpRequest.class);
    verify(httpClient, org.mockito.Mockito.atLeastOnce()).send(captor.capture(), any());
    List<HttpRequest> requests = captor.getAllValues();
    return requests.get(requests.size() - 1);
  }

  private String capturedBody() throws Exception {
    Optional<HttpRequest.BodyPublisher> publisher = capturedRequest().bodyPublisher();
    assertThat(publisher).isPresent();
    return readBody(publisher.get());
  }

  private static String readBody(HttpRequest.BodyPublisher publisher) {
    ByteArrayOutputStream collected = new ByteArrayOutputStream();
    publisher.subscribe(
        new Flow.Subscriber<java.nio.ByteBuffer>() {
          @Override
          public void onSubscribe(Flow.Subscription subscription) {
            subscription.request(Long.MAX_VALUE);
          }

          @Override
          public void onNext(java.nio.ByteBuffer item) {
            byte[] bytes = new byte[item.remaining()];
            item.get(bytes);
            collected.write(bytes, 0, bytes.length);
          }

          @Override
          public void onError(Throwable throwable) {
            throw new IllegalStateException(throwable);
          }

          @Override
          public void onComplete() {}
        });
    return new String(collected.toByteArray(), StandardCharsets.UTF_8);
  }
}
