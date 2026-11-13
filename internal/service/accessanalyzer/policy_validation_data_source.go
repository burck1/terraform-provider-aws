// Copyright IBM Corp. 2014, 2026
// SPDX-License-Identifier: MPL-2.0

package accessanalyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	awstypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-provider-aws/internal/framework"
	fwflex "github.com/hashicorp/terraform-provider-aws/internal/framework/flex"
	fwtypes "github.com/hashicorp/terraform-provider-aws/internal/framework/types"
	"github.com/hashicorp/terraform-provider-aws/internal/smerr"
	"github.com/hashicorp/terraform-provider-aws/names"
)

// @FrameworkDataSource("aws_accessanalyzer_policy_validation", name="Policy Validation")
func newPolicyValidationDataSource(context.Context) (datasource.DataSourceWithConfigure, error) {
	return &policyValidationDataSource{}, nil
}

type policyValidationDataSource struct {
	framework.DataSourceWithModel[policyValidationDataSourceModel]
}

func (d *policyValidationDataSource) Schema(ctx context.Context, request datasource.SchemaRequest, response *datasource.SchemaResponse) {
	response.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"findings": framework.DataSourceComputedListOfObjectAttribute[findingModel](ctx),
			names.AttrID: schema.StringAttribute{
				Computed: true,
			},
			names.AttrJSON: schema.StringAttribute{
				CustomType: fwtypes.IAMPolicyType,
				Computed:   true,
			},
			"locale": schema.StringAttribute{
				CustomType: fwtypes.StringEnumType[awstypes.Locale](),
				Optional:   true,
			},
			names.AttrPolicy: schema.StringAttribute{
				CustomType: fwtypes.IAMPolicyType,
				Required:   true,
			},
			"policy_type": schema.StringAttribute{
				CustomType: fwtypes.StringEnumType[awstypes.PolicyType](),
				Required:   true,
			},
			"validate_policy_resource_type": schema.StringAttribute{
				CustomType: fwtypes.StringEnumType[awstypes.ValidatePolicyResourceType](),
				Optional:   true,
			},
		},
	}
}

func (d *policyValidationDataSource) ValidateConfig(ctx context.Context, request datasource.ValidateConfigRequest, response *datasource.ValidateConfigResponse) {
	var policyType, resourceType types.String
	response.Diagnostics.Append(request.Config.GetAttribute(ctx, path.Root("policy_type"), &policyType)...)
	response.Diagnostics.Append(request.Config.GetAttribute(ctx, path.Root("validate_policy_resource_type"), &resourceType)...)
	if response.Diagnostics.HasError() {
		return
	}

	if policyType.IsUnknown() || resourceType.IsUnknown() || resourceType.IsNull() || policyType.IsNull() {
		return
	}

	if awstypes.PolicyType(policyType.ValueString()) != awstypes.PolicyTypeResourcePolicy {
		response.Diagnostics.AddAttributeError(
			path.Root("validate_policy_resource_type"),
			"Invalid Attribute Combination",
			`"validate_policy_resource_type" can only be set when "policy_type" is "RESOURCE_POLICY"`,
		)
	}
}

func (d *policyValidationDataSource) Read(ctx context.Context, request datasource.ReadRequest, response *datasource.ReadResponse) {
	var data policyValidationDataSourceModel
	smerr.AddEnrich(ctx, &response.Diagnostics, request.Config.Get(ctx, &data))
	if response.Diagnostics.HasError() {
		return
	}

	conn := d.Meta().AccessAnalyzerClient(ctx)

	policy := data.Policy.ValueString()
	input := accessanalyzer.ValidatePolicyInput{
		Locale:                     data.Locale.ValueEnum(),
		PolicyDocument:             &policy,
		PolicyType:                 data.PolicyType.ValueEnum(),
		ValidatePolicyResourceType: data.ValidatePolicyResourceType.ValueEnum(),
	}

	var findings []awstypes.ValidatePolicyFinding
	pages := accessanalyzer.NewValidatePolicyPaginator(conn, &input)
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			smerr.AddError(ctx, &response.Diagnostics, err)
			return
		}

		findings = append(findings, page.Findings...)
	}

	flattened, diags := flattenFindings(ctx, findings)
	smerr.AddEnrich(ctx, &response.Diagnostics, diags)
	if response.Diagnostics.HasError() {
		return
	}

	data.Findings = flattened
	data.ID = types.StringValue(policyValidationID(&input))
	data.JSON = data.Policy

	smerr.AddEnrich(ctx, &response.Diagnostics, response.State.Set(ctx, &data))
}

// policyValidationID returns a stable identifier derived from the request.
func policyValidationID(input *accessanalyzer.ValidatePolicyInput) string {
	h := sha256.New()
	for _, s := range []string{
		string(input.Locale),
		*input.PolicyDocument,
		string(input.PolicyType),
		string(input.ValidatePolicyResourceType),
	} {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}

	return hex.EncodeToString(h.Sum(nil))
}

func flattenFindings(ctx context.Context, apiObjects []awstypes.ValidatePolicyFinding) (fwtypes.ListNestedObjectValueOf[findingModel], diag.Diagnostics) {
	var diags diag.Diagnostics

	models := make([]*findingModel, 0, len(apiObjects))
	for _, apiObject := range apiObjects {
		locations, d := flattenLocations(ctx, apiObject.Locations)
		diags.Append(d...)
		if diags.HasError() {
			return fwtypes.NewListNestedObjectValueOfNull[findingModel](ctx), diags
		}

		models = append(models, &findingModel{
			FindingDetails: fwflex.StringToFramework(ctx, apiObject.FindingDetails),
			FindingType:    fwtypes.StringEnumValue(apiObject.FindingType),
			IssueCode:      fwflex.StringToFramework(ctx, apiObject.IssueCode),
			LearnMoreLink:  fwflex.StringToFramework(ctx, apiObject.LearnMoreLink),
			Locations:      locations,
		})
	}

	return fwtypes.NewListNestedObjectValueOfSlice(ctx, models, nil)
}

func flattenLocations(ctx context.Context, apiObjects []awstypes.Location) (fwtypes.ListNestedObjectValueOf[locationModel], diag.Diagnostics) {
	var diags diag.Diagnostics

	models := make([]*locationModel, 0, len(apiObjects))
	for _, apiObject := range apiObjects {
		elements, d := flattenPathElements(ctx, apiObject.Path)
		diags.Append(d...)

		span, d := flattenSpan(ctx, apiObject.Span)
		diags.Append(d...)
		if diags.HasError() {
			return fwtypes.NewListNestedObjectValueOfNull[locationModel](ctx), diags
		}

		models = append(models, &locationModel{
			Path: elements,
			Span: span,
		})
	}

	return fwtypes.NewListNestedObjectValueOfSlice(ctx, models, nil)
}

func flattenPathElements(ctx context.Context, apiObjects []awstypes.PathElement) (fwtypes.ListNestedObjectValueOf[pathElementModel], diag.Diagnostics) {
	var diags diag.Diagnostics

	models := make([]*pathElementModel, 0, len(apiObjects))
	for _, apiObject := range apiObjects {
		model := pathElementModel{
			Index:     types.Int64Null(),
			Key:       types.StringNull(),
			Substring: fwtypes.NewObjectValueOfNull[substringModel](ctx),
			Value:     types.StringNull(),
		}

		switch v := apiObject.(type) {
		case *awstypes.PathElementMemberIndex:
			model.Index = types.Int64Value(int64(v.Value))
		case *awstypes.PathElementMemberKey:
			model.Key = types.StringValue(v.Value)
		case *awstypes.PathElementMemberSubstring:
			substring, d := fwtypes.NewObjectValueOf(ctx, &substringModel{
				Length: fwflex.Int32ToFrameworkInt64(ctx, v.Value.Length),
				Start:  fwflex.Int32ToFrameworkInt64(ctx, v.Value.Start),
			})
			diags.Append(d...)
			model.Substring = substring
		case *awstypes.PathElementMemberValue:
			model.Value = types.StringValue(v.Value)
		}

		models = append(models, &model)
	}
	if diags.HasError() {
		return fwtypes.NewListNestedObjectValueOfNull[pathElementModel](ctx), diags
	}

	return fwtypes.NewListNestedObjectValueOfSlice(ctx, models, nil)
}

func flattenSpan(ctx context.Context, apiObject *awstypes.Span) (fwtypes.ObjectValueOf[spanModel], diag.Diagnostics) {
	var diags diag.Diagnostics

	if apiObject == nil {
		return fwtypes.NewObjectValueOfNull[spanModel](ctx), diags
	}

	start, d := flattenPosition(ctx, apiObject.Start)
	diags.Append(d...)
	end, d := flattenPosition(ctx, apiObject.End)
	diags.Append(d...)
	if diags.HasError() {
		return fwtypes.NewObjectValueOfNull[spanModel](ctx), diags
	}

	return fwtypes.NewObjectValueOf(ctx, &spanModel{
		End:   end,
		Start: start,
	})
}

func flattenPosition(ctx context.Context, apiObject *awstypes.Position) (fwtypes.ObjectValueOf[positionModel], diag.Diagnostics) {
	if apiObject == nil {
		return fwtypes.NewObjectValueOfNull[positionModel](ctx), nil
	}

	return fwtypes.NewObjectValueOf(ctx, &positionModel{
		Column: fwflex.Int32ToFrameworkInt64(ctx, apiObject.Column),
		Line:   fwflex.Int32ToFrameworkInt64(ctx, apiObject.Line),
		Offset: fwflex.Int32ToFrameworkInt64(ctx, apiObject.Offset),
	})
}

type policyValidationDataSourceModel struct {
	framework.WithRegionModel
	Findings                   fwtypes.ListNestedObjectValueOf[findingModel]           `tfsdk:"findings"`
	ID                         types.String                                            `tfsdk:"id"`
	JSON                       fwtypes.IAMPolicy                                       `tfsdk:"json"`
	Locale                     fwtypes.StringEnum[awstypes.Locale]                     `tfsdk:"locale"`
	Policy                     fwtypes.IAMPolicy                                       `tfsdk:"policy"`
	PolicyType                 fwtypes.StringEnum[awstypes.PolicyType]                 `tfsdk:"policy_type"`
	ValidatePolicyResourceType fwtypes.StringEnum[awstypes.ValidatePolicyResourceType] `tfsdk:"validate_policy_resource_type"`
}

type findingModel struct {
	FindingDetails types.String                                           `tfsdk:"finding_details"`
	FindingType    fwtypes.StringEnum[awstypes.ValidatePolicyFindingType] `tfsdk:"finding_type"`
	IssueCode      types.String                                           `tfsdk:"issue_code"`
	LearnMoreLink  types.String                                           `tfsdk:"learn_more_link"`
	Locations      fwtypes.ListNestedObjectValueOf[locationModel]         `tfsdk:"locations"`
}

type locationModel struct {
	Path fwtypes.ListNestedObjectValueOf[pathElementModel] `tfsdk:"path"`
	Span fwtypes.ObjectValueOf[spanModel]                  `tfsdk:"span"`
}

type pathElementModel struct {
	Index     types.Int64                           `tfsdk:"index"`
	Key       types.String                          `tfsdk:"key"`
	Substring fwtypes.ObjectValueOf[substringModel] `tfsdk:"substring"`
	Value     types.String                          `tfsdk:"value"`
}

type substringModel struct {
	Length types.Int64 `tfsdk:"length"`
	Start  types.Int64 `tfsdk:"start"`
}

type spanModel struct {
	End   fwtypes.ObjectValueOf[positionModel] `tfsdk:"end"`
	Start fwtypes.ObjectValueOf[positionModel] `tfsdk:"start"`
}

type positionModel struct {
	Column types.Int64 `tfsdk:"column"`
	Line   types.Int64 `tfsdk:"line"`
	Offset types.Int64 `tfsdk:"offset"`
}
