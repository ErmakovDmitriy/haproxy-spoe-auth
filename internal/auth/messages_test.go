package auth

import (
	"testing"
	"time"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/stretchr/testify/suite"
)

// Mock for ID token from go-oidc
type mockClaimSource struct {
	Endpoint    string `json:"endpoint"`
	AccessToken string `json:"access_token"`
}

type mockIDToken struct {
	Issuer            string
	Audience          []string
	Subject           string
	Expiry            time.Time
	IssuedAt          time.Time
	Nonce             string
	AccessTokenHash   string
	sigAlgorithm      string
	claims            []byte
	distributedClaims map[string]mockClaimSource
}

type TestBuildTokenClaimsSuite struct {
	suite.Suite
}

func (ts *TestBuildTokenClaimsSuite) TestClaims() {
	type testCase struct {
		claimPaths    []string
		expectedValue []action.Action
	}

	var (
		jwtToken = &mockIDToken{
			claims: []byte(`{
				"name": "user1",
				"roles": [
					"role1", "role2", "role3"
				],
				"per-service": {
					"service1": {
						"roles": ["service1-role-1", "service1-role-2"]
					},
					"service2": {
						"roles": ["service2-role-1", "service2-role-2"]
					}
				},
				"null-valued-value": null,
				"token-lifetime": 1697048435,
				"true-value": true,
				"false-value": false
			}`),
		}

		tests []*testCase = []*testCase{
			{
				claimPaths: []string{"name", "roles"},
				expectedValue: []action.Action{
					action.NewSetVar(action.ScopeSession, "token_claim_name", "user1"),
					action.NewSetVar(action.ScopeSession, "token_claim_roles", "role1,role2,role3"),
				},
			},
			{
				claimPaths: []string{"per-service.service2.roles", "per-service.non-existing-data"},
				expectedValue: []action.Action{
					action.NewSetVar(action.ScopeSession, "token_claim_per_service_service2_roles", "service2-role-1,service2-role-2"),
					// If there is no value, the variable is not set.
					// action.NewSetVar(action.ScopeSession, "token_claim_per_service_non_existing_data", ""),
				},
			},
			{
				claimPaths: []string{"null-valued-value"},
				expectedValue: []action.Action{
					action.NewSetVar(action.ScopeSession, "token_claim_null_valued_value", nil),
				},
			},
			{
				claimPaths: []string{"token-lifetime"},
				expectedValue: []action.Action{
					// Cast to "int64" because gjson parses whole numbers as int64.
					action.NewSetVar(action.ScopeSession, "token_claim_token_lifetime", int64(1697048435)),
				},
			},
			{
				claimPaths: []string{"true-value"},
				expectedValue: []action.Action{
					action.NewSetVar(action.ScopeSession, "token_claim_true_value", "true"),
				},
			},
			{
				claimPaths: []string{"false-value"},
				expectedValue: []action.Action{
					action.NewSetVar(action.ScopeSession, "token_claim_false_value", "false"),
				},
			},
			// A strange case when a user gives a path to a JSON object and not to a simple list or a value.
			{
				claimPaths: []string{"per-service.service1"},
				expectedValue: []action.Action{
					// Return JSON as is.
					action.NewSetVar(
						action.ScopeSession,
						"token_claim_per_service_service1",
						"{\n\t\t\t\t\t\t\"roles\": [\"service1-role-1\", \"service1-role-2\"]\n\t\t\t\t\t}"),
				},
			},
		}
	)

	tokenClaims, err := parseTokenClaims((*oidc.IDToken)(unsafe.Pointer(jwtToken)))
	ts.NoError(err, "Token claims must be parsed without error")

	for _, tc := range tests {
		actions := BuildTokenClaimsMessage(tokenClaims, tc.claimPaths)

		ts.Equal(tc.expectedValue, actions, "Unexpected SPOE actions")
	}
}

func TestBuildTokenClaims(t *testing.T) {
	suite.Run(t, &TestBuildTokenClaimsSuite{})
}

type TestEvaluateTokenExpressionsSuite struct {
	suite.Suite
}

func (ts *TestEvaluateTokenExpressionsSuite) TestExpressions() {
	type testCase struct {
		expressions   []OAuthTokenExpression
		expectedValue []action.Action
	}

	var (
		jwtToken = &mockIDToken{
			claims: []byte(`{
				"name": "user1",
				"roles": [
					"role1", "role2", "role3"
				],
				"per-service": {
					"service1": {
						"roles": ["service1-role-1", "service1-role-2"]
					},
					"service2": {
						"roles": ["service2-role-1", "service2-role-2"]
					}
				},
				"values-with-spaces": ["role 1", "role 2"],
				"key with spaces": ["value1"]
			}`),
		}

		tests []*testCase = []*testCase{
			{
				expressions: []OAuthTokenExpression{
					// Value is in the token.
					{
						tokenClaim: "per-service.service1.roles",
						rawValue:   "service1-role-1",
						operation:  in,
					},
					{
						tokenClaim: "per-service.service1.roles",
						rawValue:   "service1-role-1",
						operation:  notIn,
					},
					// Value is not in the token.
					{
						tokenClaim: "per-service.service1.roles",
						rawValue:   "non-existing-field",
						operation:  in,
					},
					{
						tokenClaim: "per-service.service1.roles",
						rawValue:   "non-existing-field",
						operation:  notIn,
					},
					// Path which does not exist.
					{
						tokenClaim: "email",
						operation:  doesNotExist,
					},
					{
						tokenClaim: "email",
						operation:  exists,
					},
					// Path which exists.
					{
						tokenClaim: "name",
						operation:  exists,
					},
					{
						tokenClaim: "name",
						operation:  doesNotExist,
					},
					// Path does not exist in the token.
					{
						tokenClaim: "non-existing-path.service1.roles",
						rawValue:   "non-existing-field",
						operation:  in,
					},
					{
						tokenClaim: "non-existing-path.service1.roles",
						rawValue:   "non-existing-field",
						operation:  notIn,
					},
					// Values with spaces or other characters.
					{
						tokenClaim: "values-with-spaces",
						rawValue:   "role 1",
						operation:  in,
					},
					{
						tokenClaim: "values-with-spaces",
						rawValue:   "role 1",
						operation:  notIn,
					},
					// Key with spaces.
					{
						tokenClaim: "key with spaces",
						rawValue:   "value1",
						operation:  notIn,
					},
				},
				expectedValue: []action.Action{
					action.NewSetVar(action.ScopeSession, "token_expression_in_per_service_service1_roles_service1_role_1", 1),
					action.NewSetVar(action.ScopeSession, "token_expression_notin_per_service_service1_roles_service1_role_1", 0),

					action.NewSetVar(action.ScopeSession, "token_expression_in_per_service_service1_roles_non_existing_field", 0),
					action.NewSetVar(action.ScopeSession, "token_expression_notin_per_service_service1_roles_non_existing_field", 1),

					action.NewSetVar(action.ScopeSession, "token_expression_doesnotexist_email", 1),
					action.NewSetVar(action.ScopeSession, "token_expression_exists_email", 0),

					action.NewSetVar(action.ScopeSession, "token_expression_exists_name", 1),
					action.NewSetVar(action.ScopeSession, "token_expression_doesnotexist_name", 0),

					action.NewSetVar(action.ScopeSession, "token_expression_in_non_existing_path_service1_roles_non_existing_field", 0),
					action.NewSetVar(action.ScopeSession, "token_expression_notin_non_existing_path_service1_roles_non_existing_field", 1),

					action.NewSetVar(action.ScopeSession, "token_expression_in_values_with_spaces_role_1", 1),
					action.NewSetVar(action.ScopeSession, "token_expression_notin_values_with_spaces_role_1", 0),

					action.NewSetVar(action.ScopeSession, "token_expression_notin_key_with_spaces_value1", 0),
				},
			},
		}
	)

	tokenClaims, err := parseTokenClaims((*oidc.IDToken)(unsafe.Pointer(jwtToken)))
	ts.NoError(err, "Token claims must be parsed without error")

	for _, tc := range tests {
		actions, err := EvaluateTokenExpressions(tokenClaims, tc.expressions)

		ts.NoError(err, "Must evaluate expressions without an error")
		ts.Equal(tc.expectedValue, actions, "Unexpected SPOE actions")
	}
}

func TestEvaluateTokenExpressions(t *testing.T) {
	suite.Run(t, &TestEvaluateTokenExpressionsSuite{})
}
