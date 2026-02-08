############################################################
# GitHub Actions Terraform role permissions (SNS + KMS use)
# This fixes:
#  - AuthorizationError: not authorized to perform SNS:CreateTopic
#
# Notes:
# - CreateTopic must be allowed on "*" because the topic ARN doesn't exist yet.
# - TagResource is needed because Terraform creates the topic with tags.
# - We also include minimal read/write actions commonly needed by Terraform
#   when managing SNS topics (Get/SetAttributes, DeleteTopic, ListTags).
############################################################

data "aws_iam_role" "github_actions_terraform" {
  name = "GitHubActions-Terraform-DevSecOps-Role"
}

data "aws_iam_policy_document" "github_actions_sns" {
  # Allow creating SNS topics (required)
  statement {
    sid       = "AllowSNSCreateTopic"
    effect    = "Allow"
    actions   = ["sns:CreateTopic"]
    resources = ["*"]
  }

  # Allow tagging during create/update (Terraform uses this)
  statement {
    sid    = "AllowSNSTagging"
    effect = "Allow"
    actions = [
      "sns:TagResource",
      "sns:UntagResource",
      "sns:ListTagsForResource"
    ]
    resources = ["*"]
  }

  # Allow Terraform to manage topic attributes / lifecycle
  statement {
    sid    = "AllowSNSManageTopics"
    effect = "Allow"
    actions = [
      "sns:GetTopicAttributes",
      "sns:SetTopicAttributes",
      "sns:DeleteTopic",
      "sns:ListTopics"
    ]
    resources = ["*"]
  }

  # Optional but commonly needed if you use SNS policies/subscriptions/notifications
  statement {
    sid    = "AllowSNSPoliciesAndSubscriptions"
    effect = "Allow"
    actions = [
      "sns:AddPermission",
      "sns:RemovePermission",
      "sns:Subscribe",
      "sns:Unsubscribe",
      "sns:ListSubscriptionsByTopic",
      "sns:GetSubscriptionAttributes",
      "sns:SetSubscriptionAttributes",
      "sns:Publish"
    ]
    resources = ["*"]
  }

  # If your SNS topics are encrypted with a CMK, Terraform and the service
  # may need to read key metadata and create grants.
  #
  # This is still reasonably tight for a CI role: it's KMS "use" actions,
  # NOT kms:* administration.
  statement {
    sid    = "AllowKMSUseForEncryptedSNS"
    effect = "Allow"
    actions = [
      "kms:DescribeKey",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "github_actions_sns" {
  name   = "github-actions-terraform-sns"
  role   = data.aws_iam_role.github_actions_terraform.name
  policy = data.aws_iam_policy_document.github_actions_sns.json
}
