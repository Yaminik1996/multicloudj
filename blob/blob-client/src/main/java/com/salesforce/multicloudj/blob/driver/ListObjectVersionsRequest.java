package com.salesforce.multicloudj.blob.driver;

import lombok.Getter;

/** Request for listing all versions of an object key. */
@Getter
public class ListObjectVersionsRequest {

  private final String key;
  private final Integer maxResults;

  private ListObjectVersionsRequest(Builder builder) {
    this.key = builder.key;
    this.maxResults = builder.maxResults;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private String key;
    private Integer maxResults;

    public Builder withKey(String key) {
      this.key = key;
      return this;
    }

    public Builder withMaxResults(Integer maxResults) {
      this.maxResults = maxResults;
      return this;
    }

    public ListObjectVersionsRequest build() {
      return new ListObjectVersionsRequest(this);
    }
  }
}
