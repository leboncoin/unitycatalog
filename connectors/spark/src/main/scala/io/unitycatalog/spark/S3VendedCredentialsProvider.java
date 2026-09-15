package io.unitycatalog.spark;

import io.unitycatalog.client.ApiClient;
import io.unitycatalog.client.ApiException;
import io.unitycatalog.client.api.TemporaryCredentialsApi;
import io.unitycatalog.client.model.AwsCredentials;
import io.unitycatalog.client.model.GenerateTemporaryTableCredential;
import io.unitycatalog.client.model.TableOperation;
import io.unitycatalog.client.model.TemporaryCredentials;
import io.unitycatalog.spark.auth.AuthConfigUtils;
import io.unitycatalog.spark.auth.catalog.UCTokenProvider;
import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.hadoop.conf.Configuration;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

/**
 * S3A credentials provider backed by Unity Catalog vended credentials, renewing them before they
 * expire.
 *
 * <p>Without this, the credentials UC vends at planning time are written verbatim into the plan as
 * {@code fs.s3a.access.key}/{@code secret.key}/{@code session.token}. They are scoped to roughly an
 * hour, so any stage still running past that point fails on S3 rather than on anything that looks
 * like an auth problem. Azure and GCS already went through a provider; S3 was the one cloud left
 * holding literal keys.
 *
 * <p>The provider re-requests credentials from UC on its own, which is why it is installed on the
 * executors too: it needs the catalog coordinates and the auth configuration, both carried in the
 * Hadoop configuration, and re-authenticates through {@link UCTokenProvider}.
 *
 * <p>Backport of the 0.3.x {@code AwsVendedTokenProvider} and its {@code GenericCredentialProvider}
 * base, collapsed into one class: the 0.3.x split exists to share a cache across four clouds and
 * five credential scopes, none of which applies to a table-scoped S3-only path.
 */
public class S3VendedCredentialsProvider implements AwsCredentialsProvider {

  /** Bootstrap credentials vended on the driver, so the first S3 call needs no round trip. */
  protected static final String INIT_ACCESS_KEY = "fs.s3a.uc.init.access.key";

  protected static final String INIT_SECRET_KEY = "fs.s3a.uc.init.secret.key";
  protected static final String INIT_SESSION_TOKEN = "fs.s3a.uc.init.session.token";
  protected static final String INIT_EXPIRATION_TIME = "fs.s3a.uc.init.expiration.time";

  /** Coordinates the provider needs to re-request credentials for the same scope. */
  protected static final String UC_URI = "fs.s3a.uc.uri";

  protected static final String UC_TABLE_ID = "fs.s3a.uc.table.id";
  protected static final String UC_TABLE_OPERATION = "fs.s3a.uc.table.operation";

  /** Auth configuration for the UC client, flattened under this prefix. */
  protected static final String UC_AUTH_PREFIX = "fs.s3a.uc.auth.";

  /** How long before expiry a credential is renewed. */
  protected static final String RENEWAL_LEAD_TIME_MILLIS = "fs.s3a.uc.renewal.leadTimeMillis";

  protected static final long DEFAULT_RENEWAL_LEAD_TIME_MILLIS = 60_000L;

  /**
   * Keyed by credential scope, and static because {@code generateCredentialProps} sets {@code
   * fs.s3a.impl.disable.cache=true}: Spark builds a fresh S3AFileSystem, and so a fresh provider,
   * on every resolution. An instance-level cache would never be reused, and each new FileSystem
   * would re-authenticate and re-vend.
   */
  private static final Map<CredentialScope, VendedCredentials> CACHE = new ConcurrentHashMap<>();

  private final Configuration conf;
  private final CredentialScope scope;
  private final long renewalLeadTimeMillis;

  /** Constructor signature required by Hadoop's S3A provider instantiation. */
  public S3VendedCredentialsProvider(URI uri, Configuration conf) {
    this.conf = conf;
    this.scope =
        new CredentialScope(
            conf.get(UC_URI), conf.get(UC_TABLE_ID), conf.get(UC_TABLE_OPERATION));
    this.renewalLeadTimeMillis =
        conf.getLong(RENEWAL_LEAD_TIME_MILLIS, DEFAULT_RENEWAL_LEAD_TIME_MILLIS);

    VendedCredentials bootstrap = readBootstrapCredentials(conf);
    if (bootstrap != null) {
      CACHE.putIfAbsent(scope, bootstrap);
    }
  }

  @Override
  public software.amazon.awssdk.auth.credentials.AwsCredentials resolveCredentials() {
    VendedCredentials credentials =
        CACHE.compute(
            scope,
            (key, cached) -> {
              if (cached != null && !cached.readyToRenew(renewalLeadTimeMillis)) {
                return cached;
              }
              return vend(key);
            });

    return AwsSessionCredentials.builder()
        .accessKeyId(credentials.accessKeyId)
        .secretAccessKey(credentials.secretAccessKey)
        .sessionToken(credentials.sessionToken)
        .build();
  }

  private VendedCredentials vend(CredentialScope key) {
    if (key.ucUri == null || key.tableId == null) {
      throw new IllegalStateException(
          "Cannot renew Unity Catalog credentials: "
              + UC_URI
              + " and "
              + UC_TABLE_ID
              + " are missing from the Hadoop configuration");
    }

    URI uri = URI.create(key.ucUri);
    ApiClient apiClient =
        new ApiClient().setHost(uri.getHost()).setPort(uri.getPort()).setScheme(uri.getScheme());

    Map<String, String> authConfigs = AuthConfigUtils.buildAuthConfigs(prefixedAuthOptions());
    if (!authConfigs.isEmpty()) {
      UCTokenProvider tokenProvider = UCTokenProvider.create(authConfigs);
      apiClient =
          apiClient.setRequestInterceptor(
              request -> request.header("Authorization", "Bearer " + tokenProvider.accessToken()));
    }

    TemporaryCredentials vended;
    try {
      vended =
          new TemporaryCredentialsApi(apiClient)
              .generateTemporaryTableCredentials(
                  new GenerateTemporaryTableCredential()
                      .tableId(key.tableId)
                      .operation(TableOperation.fromValue(key.operation)));
    } catch (ApiException e) {
      throw new RuntimeException(
          "Failed to renew Unity Catalog credentials for table " + key.tableId, e);
    }

    AwsCredentials aws = vended.getAwsTempCredentials();
    if (aws == null) {
      throw new IllegalStateException(
          "Unity Catalog returned no AWS credentials for table " + key.tableId);
    }
    return new VendedCredentials(
        aws.getAccessKeyId(),
        aws.getSecretAccessKey(),
        aws.getSessionToken(),
        vended.getExpirationTime());
  }

  /**
   * Re-keys the auth options from {@link #UC_AUTH_PREFIX} to the bare names {@link AuthConfigUtils}
   * expects, so the catalog and the provider share one normalization path.
   */
  private Map<String, String> prefixedAuthOptions() {
    Map<String, String> options = new HashMap<>();
    conf.getPropsWithPrefix(UC_AUTH_PREFIX).forEach(options::put);
    return options;
  }

  private static VendedCredentials readBootstrapCredentials(Configuration conf) {
    String accessKey = conf.get(INIT_ACCESS_KEY);
    String secretKey = conf.get(INIT_SECRET_KEY);
    String sessionToken = conf.get(INIT_SESSION_TOKEN);
    if (accessKey == null || secretKey == null || sessionToken == null) {
      return null;
    }
    // Absent expiry means "never renew", matching how 0.3.x treats a static credential. UC only
    // omits it for non-expiring credentials.
    long expiration = conf.getLong(INIT_EXPIRATION_TIME, Long.MAX_VALUE);
    return new VendedCredentials(accessKey, secretKey, sessionToken, expiration);
  }

  /** Test-only: the cache is static, so it outlives a single test. */
  static void clearCache() {
    CACHE.clear();
  }

  /** The resource a vended credential grants access to; two calls sharing it can share a credential. */
  private static final class CredentialScope {
    private final String ucUri;
    private final String tableId;
    private final String operation;

    CredentialScope(String ucUri, String tableId, String operation) {
      this.ucUri = ucUri;
      this.tableId = tableId;
      this.operation = operation == null ? TableOperation.READ_WRITE.getValue() : operation;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      CredentialScope that = (CredentialScope) o;
      return Objects.equals(ucUri, that.ucUri)
          && Objects.equals(tableId, that.tableId)
          && Objects.equals(operation, that.operation);
    }

    @Override
    public int hashCode() {
      return Objects.hash(ucUri, tableId, operation);
    }
  }

  private static final class VendedCredentials {
    private final String accessKeyId;
    private final String secretAccessKey;
    private final String sessionToken;
    private final Long expirationTime;

    VendedCredentials(
        String accessKeyId, String secretAccessKey, String sessionToken, Long expirationTime) {
      this.accessKeyId = accessKeyId;
      this.secretAccessKey = secretAccessKey;
      this.sessionToken = sessionToken;
      this.expirationTime = expirationTime;
    }

    boolean readyToRenew(long leadTimeMillis) {
      return expirationTime != null
          && expirationTime <= Instant.now().toEpochMilli() + leadTimeMillis;
    }
  }
}
