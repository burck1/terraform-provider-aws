// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MPL-2.0

package accessanalyzer_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-provider-aws/internal/acctest"
	"github.com/hashicorp/terraform-provider-aws/names"
)

func TestAccAccessAnalyzerPolicyValidationDataSource_basic(t *testing.T) {
	ctx := acctest.Context(t)
	dataSourceName := "data.aws_accessanalyzer_policy_validation.test"

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.AccessAnalyzerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyValidationDataSourceConfig_basic(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("findings"), knownvalue.ListExact([]knownvalue.Check{})),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New(names.AttrID), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New(names.AttrJSON), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccAccessAnalyzerPolicyValidationDataSource_findings(t *testing.T) {
	ctx := acctest.Context(t)
	dataSourceName := "data.aws_accessanalyzer_policy_validation.test"

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.AccessAnalyzerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyValidationDataSourceConfig_findings(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("findings"), knownvalue.ListPartial(map[int]knownvalue.Check{
						0: knownvalue.ObjectPartial(map[string]knownvalue.Check{
							"finding_type": knownvalue.StringExact("ERROR"),
							"issue_code":   knownvalue.NotNull(),
							"locations":    knownvalue.NotNull(),
						}),
					})),
				},
			},
		},
	})
}

func TestAccAccessAnalyzerPolicyValidationDataSource_resourceType(t *testing.T) {
	ctx := acctest.Context(t)
	dataSourceName := "data.aws_accessanalyzer_policy_validation.test"

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.AccessAnalyzerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccPolicyValidationDataSourceConfig_resourceType(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("validate_policy_resource_type"), knownvalue.StringExact("AWS::IAM::AssumeRolePolicyDocument")),
					statecheck.ExpectKnownValue(dataSourceName, tfjsonpath.New("findings"), knownvalue.NotNull()),
				},
			},
		},
	})
}

func TestAccAccessAnalyzerPolicyValidationDataSource_resourceTypeInvalidPolicyType(t *testing.T) {
	ctx := acctest.Context(t)

	acctest.ParallelTest(ctx, t, resource.TestCase{
		PreCheck:                 func() { acctest.PreCheck(ctx, t) },
		ErrorCheck:               acctest.ErrorCheck(t, names.AccessAnalyzerServiceID),
		ProtoV5ProviderFactories: acctest.ProtoV5ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      testAccPolicyValidationDataSourceConfig_resourceTypeInvalidPolicyType(),
				ExpectError: regexp.MustCompile(`can only be set when "policy_type" is "RESOURCE_POLICY"`),
			},
		},
	})
}

func testAccPolicyValidationDataSourceConfig_basic() string {
	return `
data "aws_iam_policy_document" "test" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:${data.aws_partition.current.partition}:s3:::example/*"]
  }
}

data "aws_partition" "current" {}

data "aws_accessanalyzer_policy_validation" "test" {
  policy      = data.aws_iam_policy_document.test.json
  policy_type = "IDENTITY_POLICY"
}
`
}

func testAccPolicyValidationDataSourceConfig_findings() string {
	return `
data "aws_accessanalyzer_policy_validation" "test" {
  policy_type = "IDENTITY_POLICY"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sqs:*"]
      Resource = []
    }]
  })
}
`
}

func testAccPolicyValidationDataSourceConfig_resourceType() string {
	return `
data "aws_iam_policy_document" "test" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_accessanalyzer_policy_validation" "test" {
  policy                        = data.aws_iam_policy_document.test.json
  policy_type                   = "RESOURCE_POLICY"
  validate_policy_resource_type = "AWS::IAM::AssumeRolePolicyDocument"
}
`
}

func testAccPolicyValidationDataSourceConfig_resourceTypeInvalidPolicyType() string {
	return `
data "aws_accessanalyzer_policy_validation" "test" {
  policy                        = jsonencode({ Version = "2012-10-17", Statement = [] })
  policy_type                   = "IDENTITY_POLICY"
  validate_policy_resource_type = "AWS::S3::Bucket"
}
`
}
