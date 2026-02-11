# SNS topic for notifications from GitHub Actions / pipeline (optional use)
resource "aws_sns_topic" "ci_notifications" {
  name = "${var.name_prefix}-ci-notifications"

  kms_master_key_id = aws_kms_key.logs.arn

  tags = merge(var.tags, {
    Name = "${var.name_prefix}-ci-notifications"
    Role = "notifications"
  })
}
