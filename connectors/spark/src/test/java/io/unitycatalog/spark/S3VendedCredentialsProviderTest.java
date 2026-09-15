package io.unitycatalog.spark;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Instant;
import org.apache.hadoop.conf.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

public class S3VendedCredentialsProviderTest {

  private static final URI S3_URI = URI.create("s3://bucket/table");

  @BeforeEach
  public void setUp() {
    // The cache is static, so it survives across tests.
    S3VendedCredentialsProvider.clearCache();
  }

  @Test
  public void servesTheBootstrapCredentialsWithoutCallingUc() {
    Configuration conf = bootstrapConf(farFuture());

    S3VendedCredentialsProvider provider = new S3VendedCredentialsProvider(S3_URI, conf);

    // No UC coordinates are needed while the bootstrap credentials are still valid: had it tried to
    // renew, the missing table id would have thrown.
    AwsSessionCredentials credentials = (AwsSessionCredentials) provider.resolveCredentials();
    assertThat(credentials.accessKeyId()).isEqualTo("init-access-key");
    assertThat(credentials.secretAccessKey()).isEqualTo("init-secret-key");
    assertThat(credentials.sessionToken()).isEqualTo("init-session-token");
  }

  @Test
  public void treatsAMissingExpiryAsNonExpiring() {
    Configuration conf = bootstrapConf(null);

    S3VendedCredentialsProvider provider = new S3VendedCredentialsProvider(S3_URI, conf);

    // UC omits the expiry only for credentials that do not expire, so the provider must not try to
    // renew them; that attempt would fail on the absent UC coordinates.
    assertThat(provider.resolveCredentials()).isNotNull();
  }

  @Test
  public void renewsOnceTheBootstrapCredentialsAreWithinTheLeadTime() {
    Configuration conf = bootstrapConf(Instant.now().toEpochMilli() + 5_000L);
    conf.setLong(S3VendedCredentialsProvider.RENEWAL_LEAD_TIME_MILLIS, 60_000L);
    // Deliberately no UC coordinates: reaching the renewal path is what the failure proves.
    conf.unset(S3VendedCredentialsProvider.UC_TABLE_ID);

    S3VendedCredentialsProvider provider = new S3VendedCredentialsProvider(S3_URI, conf);

    assertThatThrownBy(provider::resolveCredentials)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Cannot renew Unity Catalog credentials");
  }

  @Test
  public void sharesACachedCredentialAcrossProviderInstancesOfTheSameScope() {
    Configuration conf = bootstrapConf(farFuture());
    conf.set(S3VendedCredentialsProvider.UC_URI, "https://uc.example.com");
    conf.set(S3VendedCredentialsProvider.UC_TABLE_ID, "table-1");

    new S3VendedCredentialsProvider(S3_URI, conf).resolveCredentials();

    // fs.s3a.impl.disable.cache=true means Spark rebuilds the FileSystem, and the provider with it.
    // A second instance for the same scope must reuse the cached credential rather than re-vend,
    // which it could not do here: these credentials carry no UC-reachable endpoint.
    Configuration second = new Configuration(false);
    second.set(S3VendedCredentialsProvider.UC_URI, "https://uc.example.com");
    second.set(S3VendedCredentialsProvider.UC_TABLE_ID, "table-1");
    second.set(S3VendedCredentialsProvider.UC_TABLE_OPERATION, "READ_WRITE");

    AwsSessionCredentials credentials =
        (AwsSessionCredentials)
            new S3VendedCredentialsProvider(S3_URI, second).resolveCredentials();

    assertThat(credentials.accessKeyId()).isEqualTo("init-access-key");
  }

  @Test
  public void isolatesDifferentScopes() {
    Configuration first = bootstrapConf(farFuture());
    first.set(S3VendedCredentialsProvider.UC_URI, "https://uc.example.com");
    first.set(S3VendedCredentialsProvider.UC_TABLE_ID, "table-1");
    new S3VendedCredentialsProvider(S3_URI, first).resolveCredentials();

    // Another table must not be served table-1's credential; with no bootstrap of its own, the only
    // way forward is a renewal, which fails on the absent endpoint.
    Configuration other = new Configuration(false);
    other.set(S3VendedCredentialsProvider.UC_TABLE_ID, "table-2");

    assertThatThrownBy(() -> new S3VendedCredentialsProvider(S3_URI, other).resolveCredentials())
        .isInstanceOf(IllegalStateException.class);
  }

  private static Long farFuture() {
    return Instant.now().toEpochMilli() + 3_600_000L;
  }

  private static Configuration bootstrapConf(Long expirationTime) {
    Configuration conf = new Configuration(false);
    conf.set(S3VendedCredentialsProvider.INIT_ACCESS_KEY, "init-access-key");
    conf.set(S3VendedCredentialsProvider.INIT_SECRET_KEY, "init-secret-key");
    conf.set(S3VendedCredentialsProvider.INIT_SESSION_TOKEN, "init-session-token");
    if (expirationTime != null) {
      conf.setLong(S3VendedCredentialsProvider.INIT_EXPIRATION_TIME, expirationTime);
    }
    return conf;
  }
}
