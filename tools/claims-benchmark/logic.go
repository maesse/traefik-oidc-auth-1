package claimbench

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/spyzhov/ajson"
)

type claimAssertion struct {
	Name  string
	AnyOf []string
	AllOf []string
}

var benchmarkClaims = map[string]interface{}{
	"iss":                "https://auth.example.test/application/o/traefik/",
	"sub":                "d197065b-7951-4c08-8906-a2fb95b57d25",
	"aud":                "traefik",
	"exp":                float64(1785805200),
	"iat":                float64(1785804900),
	"email":              "mads@example.test",
	"email_verified":     true,
	"preferred_username": "mads",
	"name":               "Mads",
	"groups": []interface{}{
		"internal-users",
		"admins",
		"owners",
	},
}

var benchmarkAssertions = []claimAssertion{
	{
		Name:  "groups",
		AnyOf: []string{"admins", "owners"},
	},
}

func marshalClaims(claims map[string]interface{}) ([]byte, error) {
	return json.Marshal(claims)
}

func selectClaim(claims map[string]interface{}, name string) ([]*ajson.Node, error) {
	parsed, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	return ajson.JSONPath(parsed, fmt.Sprintf("$.%s", name))
}

// isAuthorizedJSONPath mirrors src/authorization.go's successful authorization path.
func isAuthorizedJSONPath(claims map[string]interface{}, assertions []claimAssertion) bool {
	if len(assertions) == 0 {
		return true
	}

	parsed, err := json.Marshal(claims)
	if err != nil {
		return false
	}

assertionsLoop:
	for _, assertion := range assertions {
		value, err := ajson.JSONPath(parsed, fmt.Sprintf("$.%s", assertion.Name))
		if err != nil || len(value) == 0 {
			return false
		}

		if len(assertion.AllOf) == 0 && len(assertion.AnyOf) == 0 {
			continue assertionsLoop
		}

		allMatches := make([]bool, len(assertion.AllOf))
		anyMatch := false

	matches:
		for _, val := range value {
			unpacked, err := val.Unpack()
			if err != nil {
				continue matches
			}

			switch val := unpacked.(type) {
			case []interface{}:
				mapped := make([]string, len(val))
				for i, rawVal := range val {
					mapped[i] = fmt.Sprintf("%v", rawVal)
				}

				if len(assertion.AllOf) > 0 {
					for _, assert := range assertion.AllOf {
						if !slices.Contains(mapped, assert) {
							break matches
						}
					}
				}
				if len(assertion.AnyOf) > 0 {
					for _, assert := range assertion.AnyOf {
						if slices.Contains(mapped, assert) {
							_ = strings.Join(assertion.AnyOf, ", ")
							continue assertionsLoop
						}
					}
					continue matches
				}
				continue assertionsLoop
			default:
				strVal := fmt.Sprintf("%v", val)
				if len(assertion.AnyOf) > 0 && slices.Contains(assertion.AnyOf, strVal) {
					anyMatch = true
				}
				if len(assertion.AllOf) > 0 {
					for i, assert := range assertion.AllOf {
						if assert == strVal {
							allMatches[i] = true
							break
						}
					}
				}
			}
		}

		if len(assertion.AnyOf) > 0 && anyMatch && len(assertion.AllOf) > 0 && !slices.Contains(allMatches, false) {
			continue assertionsLoop
		}
		if len(assertion.AnyOf) > 0 && anyMatch && len(assertion.AllOf) == 0 {
			continue assertionsLoop
		}
		if len(assertion.AllOf) > 0 && !slices.Contains(allMatches, false) && len(assertion.AnyOf) == 0 {
			continue assertionsLoop
		}

		return false
	}

	return true
}

func isAuthorizedDirect(claims map[string]interface{}, assertions []claimAssertion) bool {
	for _, assertion := range assertions {
		raw, ok := claims[assertion.Name]
		if !ok {
			return false
		}

		values, ok := claimStrings(raw)
		if !ok {
			return false
		}

		for _, expected := range assertion.AllOf {
			if !slices.Contains(values, expected) {
				return false
			}
		}

		if len(assertion.AnyOf) > 0 {
			matched := false
			for _, expected := range assertion.AnyOf {
				if slices.Contains(values, expected) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	return true
}

func claimStrings(raw interface{}) ([]string, bool) {
	switch value := raw.(type) {
	case []interface{}:
		result := make([]string, len(value))
		for i, item := range value {
			result[i] = fmt.Sprintf("%v", item)
		}
		return result, true
	case []string:
		return value, true
	default:
		return []string{fmt.Sprintf("%v", value)}, true
	}
}
