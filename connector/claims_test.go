package connector

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/pkg/claims"
)

func TestCopySourceClaimsCopiesOnlyConfiguredValues(t *testing.T) {
	identity := Identity{}
	err := CopySourceClaims(&identity, []string{"department"}, map[string]interface{}{
		"department": "engineering",
		"secret":     "must-not-cross",
	})
	require.NoError(t, err)
	require.Equal(t, claims.String("engineering"), identity.SourceClaims["department"])
	require.NotContains(t, identity.SourceClaims, "secret")
}

func TestCopySourceClaimsRejectsUnsupportedValues(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
	}{
		{name: "object", value: map[string]interface{}{"key": "value"}},
		{name: "nested array", value: []interface{}{[]interface{}{"value"}}},
		{name: "control character", value: "value\x00"},
		{name: "oversized string", value: strings.Repeat("x", 257)},
		{name: "oversized array", value: make([]string, 33)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := Identity{}
			err := CopySourceClaims(&identity, []string{"claim"}, map[string]interface{}{"claim": test.value})
			require.Error(t, err)
			require.Empty(t, identity.SourceClaims)
		})
	}
}
