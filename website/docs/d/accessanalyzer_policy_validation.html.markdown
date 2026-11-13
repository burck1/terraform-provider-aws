---
subcategory: "IAM Access Analyzer"
layout: "aws"
page_title: "AWS: aws_accessanalyzer_policy_validation"
description: |-
  Validates a policy document with IAM Access Analyzer and returns the findings.
---

# Data Source: aws_accessanalyzer_policy_validation

Validates a policy document with IAM Access Analyzer and returns the findings. This data source only reports findings. It does not fail when findings are returned, so use a [custom condition](https://developer.hashicorp.com/terraform/language/expressions/custom-conditions) to act on them.

## Example Usage

```terraform
data "aws_iam_policy_document" "example" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example-bucket/*"]
  }
}

data "aws_accessanalyzer_policy_validation" "example" {
  policy      = data.aws_iam_policy_document.example.json
  policy_type = "IDENTITY_POLICY"

  lifecycle {
    postcondition {
      condition     = length([for f in self.findings : f if f.finding_type == "ERROR"]) == 0
      error_message = "Policy has validation errors."
    }
  }
}

resource "aws_iam_policy" "example" {
  name   = "example"
  policy = data.aws_accessanalyzer_policy_validation.example.json
}
```

### Using a Check

A [`check` block](https://developer.hashicorp.com/terraform/language/validate#checks) reports findings as warnings without blocking the plan or apply.

```terraform
data "aws_iam_policy_document" "example" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::example-bucket/*"]
  }
}

resource "aws_iam_policy" "example" {
  name   = "example"
  policy = data.aws_iam_policy_document.example.json
}

check "example_policy_validation" {
  data "aws_accessanalyzer_policy_validation" "example" {
    policy      = aws_iam_policy.example.policy
    policy_type = "IDENTITY_POLICY"
  }

  assert {
    condition     = length(data.aws_accessanalyzer_policy_validation.example.findings) == 0
    error_message = "Policy has IAM Access Analyzer findings."
  }
}
```

### Validating a Resource Policy

```terraform
data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_accessanalyzer_policy_validation" "assume_role" {
  policy                        = data.aws_iam_policy_document.assume_role.json
  policy_type                   = "RESOURCE_POLICY"
  validate_policy_resource_type = "AWS::IAM::AssumeRolePolicyDocument"
}

resource "aws_iam_role" "example" {
  name               = "example"
  assume_role_policy = data.aws_accessanalyzer_policy_validation.assume_role.json
}
```

## Argument Reference

The following arguments are required:

* `policy` - (Required) JSON policy document to validate.
* `policy_type` - (Required) Type of policy to validate. Valid values are `IDENTITY_POLICY`, `RESOURCE_POLICY`, `SERVICE_CONTROL_POLICY`, and `RESOURCE_CONTROL_POLICY`.

The following arguments are optional:

* `locale` - (Optional) Locale used to localize the findings. Valid values are `DE`, `EN`, `ES`, `FR`, `IT`, `JA`, `KO`, `PT_BR`, `ZH_CN`, and `ZH_TW`.
* `region` - (Optional) Region where this resource will be [managed](https://docs.aws.amazon.com/general/latest/gr/rande.html#regional-endpoints). Defaults to the Region set in the [provider configuration](https://registry.terraform.io/providers/hashicorp/aws/latest/docs#aws-configuration-reference).
* `validate_policy_resource_type` - (Optional) Type of resource the policy will be attached to. Can only be set when `policy_type` is `RESOURCE_POLICY`. Valid values are `AWS::S3::Bucket`, `AWS::S3::AccessPoint`, `AWS::S3::MultiRegionAccessPoint`, `AWS::S3ObjectLambda::AccessPoint`, `AWS::IAM::AssumeRolePolicyDocument`, and `AWS::DynamoDB::Table`. For other resource types, omit this argument and IAM Access Analyzer runs the checks that apply to all resource policies.

## Attribute Reference

This data source exports the following attributes in addition to the arguments above:

* `findings` - List of findings returned by IAM Access Analyzer. See [`findings` Block](#findings-block) below.
* `id` - Identifier derived from the arguments.
* `json` - Policy document that was validated, unchanged. Reference this attribute to make a resource depend on the validation.

### `findings` Block

The `findings` block exports:

* `finding_details` - Localized message that explains the finding and how to address it.
* `finding_type` - Impact of the finding. One of `ERROR`, `SECURITY_WARNING`, `SUGGESTION`, or `WARNING`.
* `issue_code` - Identifier of the issue associated with the finding.
* `learn_more_link` - Link to documentation about the type of finding.
* `locations` - Locations in the policy document related to the finding. See [`locations` Block](#locations-block) below.

### `locations` Block

The `locations` block exports:

* `path` - Path through the JSON representation of the policy. See [`path` Block](#path-block) below.
* `span` - Span in the policy document. See [`span` Block](#span-block) below.

### `path` Block

Each element of `path` sets one of `index`, `key`, `substring`, or `value`. The others are null.

The `path` block exports:

* `index` - Index in a JSON array.
* `key` - Key in a JSON object.
* `substring` - Substring of a literal string in a JSON object. See [`substring` Block](#substring-block) below.
* `value` - Value associated with a key in a JSON object.

### `span` Block

The `span` block exports:

* `end` - End position of the span, exclusive. See [`position` Block](#position-block) below.
* `start` - Start position of the span, inclusive. See [`position` Block](#position-block) below.

### `substring` Block

The `substring` block exports:

* `length` - Length of the substring.
* `start` - Start index of the substring, starting from `0`.

### `position` Block

The `start` and `end` positions export:

* `column` - Column of the position, starting from `0`.
* `line` - Line of the position, starting from `1`.
* `offset` - Offset within the policy document, starting from `0`.
