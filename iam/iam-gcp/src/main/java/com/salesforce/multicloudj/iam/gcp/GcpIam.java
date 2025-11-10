package com.salesforce.multicloudj.iam.gcp;

import com.google.api.gax.rpc.ApiException;
import com.google.auto.service.AutoService;
import com.google.cloud.resourcemanager.v3.ProjectsClient;
import com.google.iam.v1.Binding;
import com.google.iam.v1.GetIamPolicyRequest;
import com.google.iam.v1.Policy;
import com.google.iam.v1.SetIamPolicyRequest;

import com.salesforce.multicloudj.common.exceptions.InvalidArgumentException;
import com.salesforce.multicloudj.common.exceptions.SubstrateSdkException;
import com.salesforce.multicloudj.common.exceptions.UnSupportedOperationException;
import com.salesforce.multicloudj.common.exceptions.UnknownException;
import com.salesforce.multicloudj.common.gcp.CommonErrorCodeMapping;
import com.salesforce.multicloudj.common.gcp.GcpConstants;
import com.salesforce.multicloudj.iam.driver.AbstractIam;
import com.salesforce.multicloudj.iam.model.CreateOptions;
import com.salesforce.multicloudj.iam.model.PolicyDocument;
import com.salesforce.multicloudj.iam.model.Statement;
import com.salesforce.multicloudj.iam.model.TrustConfiguration;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@SuppressWarnings("rawtypes")
@AutoService(AbstractIam.class)
public class GcpIam extends AbstractIam<GcpIam> {
  private ProjectsClient projectsClient;

  public GcpIam(Builder builder) {
    super(builder);
    try {
      this.projectsClient = ProjectsClient.create();
    } catch (IOException e) {
      throw new SubstrateSdkException("Could not create ProjectsClient", e);
    }
  }

  public GcpIam() {
    super(new Builder());
    try {
      this.projectsClient = ProjectsClient.create();
    } catch (IOException e) {
      throw new SubstrateSdkException("Could not create ProjectsClient", e);
    }
  }

  public GcpIam(Builder builder, ProjectsClient projectsClient) {
    super(builder);
    if (projectsClient == null) {
      throw new InvalidArgumentException("ProjectsClient cannot be null");
    }
    this.projectsClient = projectsClient;
  }

  @Override
  protected String doCreateIdentity(String identityName, String description, String tenantId,
      String region, Optional<TrustConfiguration> trustConfig,
      Optional<CreateOptions> options) {
    // TODO: Implement GCP service account creation
    throw new UnSupportedOperationException("doCreateIdentity not yet implemented for GCP");
  }

  /**
   * Attaches an inline policy to a resource.
   * This implementation treats each action in the PolicyDocument statement as a GCP IAM role name
   * and grants that role to the service account. The action values are used directly as role names
   * (e.g., "roles/iam.serviceAccountUser", "roles/storage.objectViewer").
   *
   * <p>Note: GCP IAM is deny-by-default: access is denied unless explicitly allowed via bindings.
   *
   * @param policyDocument the policy document where actions are treated as GCP IAM role names
   * @param tenantId the tenant ID (project resource name, e.g., "projects/my-project")
   * @param region the region (optional for GCP)
   * @param resource the service account email (complete format, e.g.,
   *     "my-sa@project.iam.gserviceaccount.com")
   */
  @Override
  protected void doAttachInlinePolicy(PolicyDocument policyDocument, String tenantId,
      String region, String resource) {
    // Get the current IAM policy for the project
    GetIamPolicyRequest getRequest = GetIamPolicyRequest.newBuilder()
        .setResource(tenantId)
        .build();
    Policy policy = projectsClient.getIamPolicy(getRequest);

    if (policy == null) {
      policy = Policy.newBuilder().build();
    }

    // Process each statement in the policy document
    for (Statement statement : policyDocument.getStatements()) {
      if (!"Allow".equalsIgnoreCase(statement.getEffect())) {
        continue;
      }

      // Treat each action as a GCP IAM role name
      for (String action : statement.getActions()) {
        String role = action;
        String member = "serviceAccount:" + resource;
        policy = addBinding(policy, role, member);
      }
    }

    // Set the updated policy back to the project
    SetIamPolicyRequest setRequest = SetIamPolicyRequest.newBuilder()
        .setResource(tenantId)
        .setPolicy(policy)
        .build();
    projectsClient.setIamPolicy(setRequest);
  }

  /**
   * Adds a binding to the IAM policy, merging with existing bindings for the same role.
   * This prevents policy bloat and avoids hitting GCP's IAM policy size limits.
   *
   * @param policy the current IAM policy
   * @param role the IAM role to grant (e.g., "roles/iam.serviceAccountUser")
   * @param member the member (service account) to grant the role to
   * @return the updated policy with the new binding
   */
  private Policy addBinding(Policy policy, String role, String member) {
    // Find existing binding for this role
    Optional<Binding> existingBinding = policy.getBindingsList().stream()
        .filter(binding -> binding.getRole().equals(role))
        .findFirst();

    if (existingBinding.isPresent()) {
      // Update existing binding if member is not already present
      Binding binding = existingBinding.get();
      if (!binding.getMembersList().contains(member)) {
        Binding updatedBinding = binding.toBuilder().addMembers(member).build();
        List<Binding> updatedBindings = policy.getBindingsList().stream()
            .map(b -> b.getRole().equals(role) ? updatedBinding : b)
            .collect(Collectors.toList());

        return policy.toBuilder()
            .clearBindings()
            .addAllBindings(updatedBindings)
            .build();
      }
      // Member already exists, return policy unchanged
      return policy;
    }

    // No existing binding for this role, create a new one
    return policy.toBuilder()
        .addBindings(Binding.newBuilder()
            .setRole(role)
            .addMembers(member)
            .build())
        .build();
  }

  @Override
  protected String doGetInlinePolicyDetails(String identityName, String policyName,
      String tenantId, String region) {
    // TODO: Implement GCP inline policy details retrieval
    throw new UnSupportedOperationException("doGetInlinePolicyDetails not yet implemented for GCP");
  }

  @Override
  protected List<String> doGetAttachedPolicies(String identityName, String tenantId,
      String region) {
    // TODO: Implement GCP attached policies retrieval
    throw new UnSupportedOperationException("doGetAttachedPolicies not yet implemented for GCP");
  }

  @Override
  protected void doRemovePolicy(String identityName, String policyName, String tenantId,
      String region) {
    // TODO: Implement GCP policy removal
    throw new UnSupportedOperationException("doRemovePolicy not yet implemented for GCP");
  }

  @Override
  protected void doDeleteIdentity(String identityName, String tenantId, String region) {
    // TODO: Implement GCP service account deletion
    throw new UnSupportedOperationException("doDeleteIdentity not yet implemented for GCP");
  }

  @Override
  protected String doGetIdentity(String identityName, String tenantId, String region) {
    // TODO: Implement GCP service account retrieval
    throw new UnSupportedOperationException("doGetIdentity not yet implemented for GCP");
  }

  @Override
  public Class<? extends SubstrateSdkException> getException(Throwable t) {
    if (t instanceof ApiException) {
      ApiException exception = (ApiException) t;
      return CommonErrorCodeMapping.getException(exception.getStatusCode().getCode());
    }
    return UnknownException.class;
  }

  @Override
  public Builder builder() {
    return new Builder();
  }

  public static class Builder extends AbstractIam.Builder<GcpIam, Builder> {
    protected Builder() {
      providerId(GcpConstants.PROVIDER_ID);
    }

    @Override
    public Builder self() {
      return this;
    }

    @Override
    public GcpIam build() {
      return new GcpIam(this);
    }
  }
}
