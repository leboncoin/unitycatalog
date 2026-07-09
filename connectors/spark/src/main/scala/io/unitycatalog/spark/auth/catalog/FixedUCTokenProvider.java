package io.unitycatalog.spark.auth.catalog;

import org.sparkproject.guava.base.Preconditions;

/** A {@link UCTokenProvider} that always returns a pre-configured static token. */
public class FixedUCTokenProvider implements UCTokenProvider {
  private final String token;

  public FixedUCTokenProvider(String token) {
    Preconditions.checkNotNull(token, "Token must not be null");
    this.token = token;
  }

  @Override
  public String accessToken() {
    return token;
  }
}
