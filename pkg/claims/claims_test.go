package claims

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClone(t *testing.T) {
	original := JSONClaims{"name": json.RawMessage(`"Ada"`)}
	clone := original.Clone()
	clone["name"][1] = 'E'
	clone["new"] = json.RawMessage(`true`)

	require.Equal(t, JSONClaims{"name": json.RawMessage(`"Ada"`)}, original)
	require.Equal(t, json.RawMessage(`"Eda"`), clone["name"])
}

func TestValidateScalarOrArray(t *testing.T) {
	valid := []string{`"value"`, `true`, `12.5`, `["one", false, 2]`}
	for _, value := range valid {
		require.NoError(t, ValidateScalarOrArray(json.RawMessage(value), 20, 3), value)
	}

	invalid := []string{`{"nested":true}`, `[["nested"]]`, `null`, `"line\nvalue"`, `["one", "two", "three", "four"]`}
	for _, value := range invalid {
		require.Error(t, ValidateScalarOrArray(json.RawMessage(value), 20, 3), value)
	}
}
