package auth

import (
	"testing"
	"time"
	"unsafe"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/negasus/haproxy-spoe-go/action"
	"github.com/stretchr/testify/suite"
)

type TestBuildTokenClaimsSuite struct {
	suite.Suite
}

func (ts *TestBuildTokenClaimsSuite) TestClaims() {
	type testCase struct {
		claimPaths    []string
		expectedValue []action.Action
	}

	// Mock for ID token from go-oidc
	type claimSource struct {
		Endpoint    string `json:"endpoint"`
		AccessToken string `json:"access_token"`
	}

	type IDToken struct {
		Issuer            string
		Audience          []string
		Subject           string
		Expiry            time.Time
		IssuedAt          time.Time
		Nonce             string
		AccessTokenHash   string
		sigAlgorithm      string
		claims            []byte
		distributedClaims map[string]claimSource
	}

	var (
		jwtToken = &IDToken{
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
				}
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
