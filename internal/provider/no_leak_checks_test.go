// Copyright (c) 2026 mikeastwood
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	tfjson "github.com/hashicorp/terraform-json"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
)

// expectAbsentFromState fails when value appears anywhere in the JSON
// rendering of the state.
func expectAbsentFromState(value string) statecheck.StateCheck {
	return absentCheck{value: value}
}

// expectAbsentFromPlan fails when value appears anywhere in the JSON
// rendering of the plan.
func expectAbsentFromPlan(value string) plancheck.PlanCheck {
	return absentCheck{value: value}
}

type absentCheck struct {
	value string
}

func (c absentCheck) CheckState(_ context.Context, req statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	resp.Error = c.check("state", req.State)
}

func (c absentCheck) CheckPlan(_ context.Context, req plancheck.CheckPlanRequest, resp *plancheck.CheckPlanResponse) {
	resp.Error = c.check("plan", req.Plan)
}

func (c absentCheck) check(what string, v any) error {
	if c.value == "" {
		return fmt.Errorf("absent check for the %s needs a non-empty value", what)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("rendering the %s as JSON: %w", what, err)
	}
	if strings.Contains(string(raw), c.value) {
		return fmt.Errorf("the secret appears in the %s", what)
	}
	return nil
}

// The checks above are what the acceptance tests rely on to prove that a
// secret never reaches the state or the plan, so prove they do catch one.
func TestAbsentChecksDetectSecret(t *testing.T) {
	t.Parallel()
	const secret = "test-secret-value"
	ctx := context.Background()

	leakyState := &tfjson.State{Values: &tfjson.StateValues{RootModule: &tfjson.StateModule{
		Resources: []*tfjson.StateResource{{Address: "echo.test", AttributeValues: map[string]any{"data": secret}}},
	}}}
	var stateResp statecheck.CheckStateResponse
	expectAbsentFromState(secret).CheckState(ctx, statecheck.CheckStateRequest{State: leakyState}, &stateResp)
	if stateResp.Error == nil {
		t.Fatal("the state check missed a secret in the state")
	}
	if strings.Contains(stateResp.Error.Error(), secret) {
		t.Fatal("the state check's error repeats the secret")
	}

	leakyPlan := &tfjson.Plan{PlannedValues: &tfjson.StateValues{RootModule: &tfjson.StateModule{
		Resources: []*tfjson.StateResource{{Address: "echo.test", AttributeValues: map[string]any{"data": secret}}},
	}}}
	var planResp plancheck.CheckPlanResponse
	expectAbsentFromPlan(secret).CheckPlan(ctx, plancheck.CheckPlanRequest{Plan: leakyPlan}, &planResp)
	if planResp.Error == nil {
		t.Fatal("the plan check missed a secret in the plan")
	}

	var cleanResp statecheck.CheckStateResponse
	expectAbsentFromState("something-else").CheckState(ctx, statecheck.CheckStateRequest{State: leakyState}, &cleanResp)
	if cleanResp.Error != nil {
		t.Fatalf("the state check flagged a value that is not there: %v", cleanResp.Error)
	}
}
