package com.salesforce.multicloudj.iam.gcp;

import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.StatusCode;
import com.google.cloud.resourcemanager.v3.ProjectsClient;
import com.google.iam.v1.Binding;
import com.google.iam.v1.GetIamPolicyRequest;
import com.google.iam.v1.Policy;
import com.google.iam.v1.SetIamPolicyRequest;

import com.salesforce.multicloudj.common.exceptions.DeadlineExceededException;
import com.salesforce.multicloudj.common.exceptions.FailedPreconditionException;
import com.salesforce.multicloudj.common.exceptions.InvalidArgumentException;
import com.salesforce.multicloudj.common.exceptions.ResourceAlreadyExistsException;
import com.salesforce.multicloudj.common.exceptions.ResourceExhaustedException;
import com.salesforce.multicloudj.common.exceptions.ResourceNotFoundException;
import com.salesforce.multicloudj.common.exceptions.SubstrateSdkException;
import com.salesforce.multicloudj.common.exceptions.UnAuthorizedException;
import com.salesforce.multicloudj.common.exceptions.UnSupportedOperationException;
import com.salesforce.multicloudj.common.exceptions.UnknownException;
import com.salesforce.multicloudj.iam.model.PolicyDocument;
import com.salesforce.multicloudj.iam.model.Statement;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class GcpIamTest {

  private static ProjectsClient mockProjectsClient;
  private GcpIam gcpIam;
  private static final String TEST_TENANT_ID = "projects/test-project";
  private static final String TEST_REGION = "us-west1";
  private static final String TEST_SERVICE_ACCOUNT = "test-sa@test-project.iam.gserviceaccount.com";
  private static final String TEST_ROLE = "roles/iam.serviceAccountUser";

  @BeforeAll
  static void setUp() {
    mockProjectsClient = Mockito.mock(ProjectsClient.class);
  }

  @BeforeEach
  void setUpEach() {
    Mockito.reset(mockProjectsClient);
    gcpIam = new GcpIam(new GcpIam.Builder(), mockProjectsClient);
  }

  @Test
  void testConstructorWithBuilderAndProjectsClient() {
    GcpIam iam = new GcpIam(new GcpIam.Builder(), mockProjectsClient);
    Assertions.assertNotNull(iam);
    Assertions.assertEquals("gcp", iam.getProviderId());
  }

  @Test
  void testConstructorWithNullProjectsClient() {
    Assertions.assertThrows(InvalidArgumentException.class, () -> {
      new GcpIam(new GcpIam.Builder(), null);
    }, "Should throw InvalidArgumentException when ProjectsClient is null");
  }

  @Test
  void testConstructorWithBuilder() throws IOException {
    try (MockedStatic<ProjectsClient> mockedClient = mockStatic(ProjectsClient.class)) {
      ProjectsClient mockClient = mock(ProjectsClient.class);
      mockedClient.when(ProjectsClient::create).thenReturn(mockClient);

      GcpIam iam = new GcpIam(new GcpIam.Builder());
      Assertions.assertNotNull(iam);
      Assertions.assertEquals("gcp", iam.getProviderId());
    }
  }

  @Test
  void testDoAttachInlinePolicySuccess() {
    // Setup: Create a policy with existing bindings
    Policy existingPolicy = Policy.newBuilder()
        .addBindings(Binding.newBuilder()
            .setRole("roles/storage.objectViewer")
            .addMembers("serviceAccount:other@test-project.iam.gserviceaccount.com")
            .build())
        .build();

    when(mockProjectsClient.getIamPolicy(any(GetIamPolicyRequest.class))).thenReturn(existingPolicy);
    when(mockProjectsClient.setIamPolicy(any(SetIamPolicyRequest.class))).thenReturn(existingPolicy);

    // Create policy document
    PolicyDocument policyDocument = PolicyDocument.builder()
        .version("2024-01-01")
        .statement(Statement.builder()
            .sid("TestPolicy")
            .effect("Allow")
            .action(TEST_ROLE)
            .build())
        .build();

    // Execute
    Assertions.assertDoesNotThrow(() -> {
      gcpIam.doAttachInlinePolicy(policyDocument, TEST_TENANT_ID, TEST_REGION, TEST_SERVICE_ACCOUNT);
    });

    // Verify
    verify(mockProjectsClient, times(1)).getIamPolicy(any(GetIamPolicyRequest.class));
    ArgumentCaptor<SetIamPolicyRequest> setRequestCaptor = ArgumentCaptor.forClass(SetIamPolicyRequest.class);
    verify(mockProjectsClient, times(1)).setIamPolicy(setRequestCaptor.capture());

    SetIamPolicyRequest setRequest = setRequestCaptor.getValue();
    Assertions.assertEquals(TEST_TENANT_ID, setRequest.getResource());
    Policy updatedPolicy = setRequest.getPolicy();
    Assertions.assertNotNull(updatedPolicy);

    // Verify the new binding was added
    boolean foundBinding = false;
    for (Binding binding : updatedPolicy.getBindingsList()) {
      if (binding.getRole().equals(TEST_ROLE)) {
        Assertions.assertTrue(binding.getMembersList().contains("serviceAccount:" + TEST_SERVICE_ACCOUNT));
        foundBinding = true;
      }
    }
    Assertions.assertTrue(foundBinding, "New binding should be added");
  }

  @Test
  void testDoAttachInlinePolicyWithNullPolicy() {
    when(mockProjectsClient.getIamPolicy(any(GetIamPolicyRequest.class))).thenReturn(null);
    when(mockProjectsClient.setIamPolicy(any(SetIamPolicyRequest.class))).thenReturn(Policy.newBuilder().build());

    PolicyDocument policyDocument = PolicyDocument.builder()
        .version("2024-01-01")
        .statement(Statement.builder()
            .sid("TestPolicy")
            .effect("Allow")
            .action(TEST_ROLE)
            .build())
        .build();

    Assertions.assertDoesNotThrow(() -> {
      gcpIam.doAttachInlinePolicy(policyDocument, TEST_TENANT_ID, TEST_REGION, TEST_SERVICE_ACCOUNT);
    });

    verify(mockProjectsClient, times(1)).setIamPolicy(any(SetIamPolicyRequest.class));
  }

  @Test
  void testDoAttachInlinePolicyMergesExistingBinding() {
    // Setup: Create a policy with existing binding for the same role
    Policy existingPolicy = Policy.newBuilder()
        .addBindings(Binding.newBuilder()
            .setRole(TEST_ROLE)
            .addMembers("serviceAccount:existing@test-project.iam.gserviceaccount.com")
            .build())
        .build();

    when(mockProjectsClient.getIamPolicy(any(GetIamPolicyRequest.class))).thenReturn(existingPolicy);
    when(mockProjectsClient.setIamPolicy(any(SetIamPolicyRequest.class))).thenReturn(existingPolicy);

    PolicyDocument policyDocument = PolicyDocument.builder()
        .version("2024-01-01")
        .statement(Statement.builder()
            .sid("TestPolicy")
            .effect("Allow")
            .action(TEST_ROLE)
            .build())
        .build();

    Assertions.assertDoesNotThrow(() -> {
      gcpIam.doAttachInlinePolicy(policyDocument, TEST_TENANT_ID, TEST_REGION, TEST_SERVICE_ACCOUNT);
    });

    ArgumentCaptor<SetIamPolicyRequest> setRequestCaptor = ArgumentCaptor.forClass(SetIamPolicyRequest.class);
    verify(mockProjectsClient, times(1)).setIamPolicy(setRequestCaptor.capture());

    Policy updatedPolicy = setRequestCaptor.getValue().getPolicy();
    Binding updatedBinding = updatedPolicy.getBindingsList().stream()
        .filter(b -> b.getRole().equals(TEST_ROLE))
        .findFirst()
        .orElse(null);

    Assertions.assertNotNull(updatedBinding);
    Assertions.assertEquals(2, updatedBinding.getMembersCount(), "Should have both existing and new members");
    Assertions.assertTrue(updatedBinding.getMembersList().contains("serviceAccount:" + TEST_SERVICE_ACCOUNT));
  }


  @Test
  void testDoAttachInlinePolicySkipsDenyStatements() {
    Policy existingPolicy = Policy.newBuilder().build();
    when(mockProjectsClient.getIamPolicy(any(GetIamPolicyRequest.class))).thenReturn(existingPolicy);
    when(mockProjectsClient.setIamPolicy(any(SetIamPolicyRequest.class))).thenReturn(existingPolicy);

    PolicyDocument policyDocument = PolicyDocument.builder()
        .version("2024-01-01")
        .statement(Statement.builder()
            .sid("DenyPolicy")
            .effect("Deny")
            .action(TEST_ROLE)
            .build())
        .build();

    Assertions.assertDoesNotThrow(() -> {
      gcpIam.doAttachInlinePolicy(policyDocument, TEST_TENANT_ID, TEST_REGION, TEST_SERVICE_ACCOUNT);
    });

    ArgumentCaptor<SetIamPolicyRequest> setRequestCaptor = ArgumentCaptor.forClass(SetIamPolicyRequest.class);
    verify(mockProjectsClient, times(1)).setIamPolicy(setRequestCaptor.capture());

    Policy updatedPolicy = setRequestCaptor.getValue().getPolicy();
    Assertions.assertEquals(0, updatedPolicy.getBindingsCount(), "Deny statements should be skipped");
  }

  @Test
  void testGetExceptionWithApiException() {
    // Test various status codes
    assertExceptionMapping(StatusCode.Code.CANCELLED, UnknownException.class);
    assertExceptionMapping(StatusCode.Code.UNKNOWN, UnknownException.class);
    assertExceptionMapping(StatusCode.Code.INVALID_ARGUMENT, InvalidArgumentException.class);
    assertExceptionMapping(StatusCode.Code.DEADLINE_EXCEEDED, DeadlineExceededException.class);
    assertExceptionMapping(StatusCode.Code.NOT_FOUND, ResourceNotFoundException.class);
    assertExceptionMapping(StatusCode.Code.ALREADY_EXISTS, ResourceAlreadyExistsException.class);
    assertExceptionMapping(StatusCode.Code.PERMISSION_DENIED, UnAuthorizedException.class);
    assertExceptionMapping(StatusCode.Code.RESOURCE_EXHAUSTED, ResourceExhaustedException.class);
    assertExceptionMapping(StatusCode.Code.FAILED_PRECONDITION, FailedPreconditionException.class);
    assertExceptionMapping(StatusCode.Code.ABORTED, DeadlineExceededException.class);
    assertExceptionMapping(StatusCode.Code.OUT_OF_RANGE, InvalidArgumentException.class);
    assertExceptionMapping(StatusCode.Code.UNIMPLEMENTED, UnSupportedOperationException.class);
    assertExceptionMapping(StatusCode.Code.INTERNAL, UnknownException.class);
    assertExceptionMapping(StatusCode.Code.UNAVAILABLE, UnknownException.class);
    assertExceptionMapping(StatusCode.Code.DATA_LOSS, UnknownException.class);
    assertExceptionMapping(StatusCode.Code.UNAUTHENTICATED, UnAuthorizedException.class);
  }

  @Test
  void testGetExceptionWithNonApiException() {
    Class<? extends SubstrateSdkException> exceptionClass = gcpIam.getException(new RuntimeException("Test error"));
    Assertions.assertEquals(UnknownException.class, exceptionClass);
  }

  @Test
  void testBuilder() {
    GcpIam.Builder builder = gcpIam.builder();
    Assertions.assertNotNull(builder);
    Assertions.assertInstanceOf(GcpIam.Builder.class, builder);
  }



  private void assertExceptionMapping(StatusCode.Code statusCode,
      Class<? extends SubstrateSdkException> expectedExceptionClass) {
    ApiException apiException = mock(ApiException.class);
    StatusCode mockStatusCode = mock(StatusCode.class);
    when(apiException.getStatusCode()).thenReturn(mockStatusCode);
    when(mockStatusCode.getCode()).thenReturn(statusCode);

    Class<? extends SubstrateSdkException> actualExceptionClass =
        gcpIam.getException(apiException);
    Assertions.assertEquals(expectedExceptionClass, actualExceptionClass,
        "Expected " + expectedExceptionClass.getSimpleName() + " for status code "
            + statusCode);
  }
}

